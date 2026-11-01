"""AirPlay 2 buffered audio sender: AAC over TCP, as iOS streams most apps.

Pairing and the encrypted RTSP connection come from pyatv; the buffered stream (stream type 103), which pyatv
cannot send, is done here.

Usage: send_buffered.py <host> <port> <file.aac (ADTS)> [--pause] [--remote-control]

--remote-control opens a second session during playback, only to control it, as iOS does; playback goes on.
"""
import asyncio
import os
import plistlib
import struct
import sys
import time
import uuid

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from pyatv.auth.hap_pairing import TRANSIENT_CREDENTIALS
from pyatv.protocols.airplay.auth import verify_connection
from pyatv.protocols.raop.protocols import TimingServer
from pyatv.support.http import http_connect
from pyatv.support.rtsp import RtspSession

NTP_UNIX_OFFSET = 2208988800
FRAMES_PER_PACKET = 1024
SAMPLE_RATE = 44100


def read_adts(path):
    """Raw AAC frames of an ADTS file"""
    data = open(path, "rb").read()
    frames = []
    offset = 0
    while offset + 7 <= len(data):
        assert data[offset] == 0xFF and (data[offset + 1] & 0xF0) == 0xF0, "not ADTS"
        header = 7 if data[offset + 1] & 1 else 9
        length = ((data[offset + 3] & 3) << 11) | (data[offset + 4] << 3) | (data[offset + 5] >> 5)
        frames.append(data[offset + header : offset + length])
        offset += length
    return frames


def plist(value):
    return plistlib.dumps(value, fmt=plistlib.FMT_BINARY)


async def exchange(rtsp, method, body=None, uri=None):
    response = await rtsp.exchange(
        method,
        uri=uri,
        content_type="application/x-apple-binary-plist" if body is not None else None,
        body=plist(body) if body is not None else None,
    )
    if response.code != 200:
        raise RuntimeError(f"{method} failed: {response.code}")
    return plistlib.loads(response.body) if response.body else {}


def network_time(seconds_from_now):
    now = time.time() + seconds_from_now
    seconds = int(now)
    return seconds + NTP_UNIX_OFFSET, int((now - seconds) * (1 << 64))


async def main():
    host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    pause = "--pause" in sys.argv
    remote_control = "--remote-control" in sys.argv
    frames = read_adts(path)
    loop = asyncio.get_running_loop()

    connection = await http_connect(host, port)
    rtsp = RtspSession(connection)
    await verify_connection(TRANSIENT_CREDENTIALS, connection)  # Transient pairing, then encrypted
    timing, _ = await loop.create_datagram_endpoint(TimingServer, local_addr=(connection.local_ip, 0))
    timing_port = timing.get_extra_info("socket").getsockname()[1]

    session = await exchange(
        rtsp,
        "SETUP",
        {"deviceID": "AA:BB:CC:DD:EE:FF", "sessionUUID": str(uuid.uuid4()).upper(), "timingPort": timing_port,
         "timingProtocol": "NTP", "name": "buffered test", "model": "iPhone17,3"},
    )
    _, events = await asyncio.open_connection(host, session["eventPort"])
    await asyncio.sleep(0.2)
    await exchange(rtsp, "RECORD")

    key = os.urandom(32)
    stream = await exchange(
        rtsp,
        "SETUP",
        {"streams": [{"type": 103, "ct": 4, "audioFormat": 0x400000, "spf": FRAMES_PER_PACKET, "shk": key,
                      "audioMode": "default", "isMedia": True, "supportsDynamicStreamID": True}]},
    )
    data_port = stream["streams"][0]["dataPort"]
    print("buffer size", stream["streams"][0].get("audioBufferSize"))
    _, data = await asyncio.open_connection(host, data_port)

    cipher = ChaCha20Poly1305(key)
    ssrc = 0x12345678
    first_rtp = 1000000

    async def send(index, audio=None):
        rtp = first_rtp + index * FRAMES_PER_PACKET
        header = struct.pack(">BBHII", 0x80, 0x60, 0, rtp, ssrc)
        header = header[:1] + struct.pack(">I", index + 1)[1:] + header[4:]  # 24-bit sequence number
        nonce = struct.pack("<Q", index)
        sealed = cipher.encrypt(b"\0\0\0\0" + nonce, frames[index] if audio is None else audio, header[4:12])
        packet = header + sealed + nonce
        data.write(struct.pack(">H", len(packet) + 2) + packet)
        await data.drain()

    # Some audio ahead, then playback starts half a second from now while the rest follows as the buffer drains
    for i in range(min(20, len(frames))):
        await send(i)
    seconds, fraction = network_time(0.5)
    await exchange(rtsp, "SETRATEANCHORTIME", {"rate": 1, "rtpTime": first_rtp, "networkTimeSecs": seconds,
                                                "networkTimeFrac": fraction, "networkTimeTimelineID": 1})
    start = time.time() + 0.5
    for i in range(20, len(frames)):
        if i == 100:
            await send(i, b"")  # As iOS sends after a flush: no audio, to be skipped
        if i == 120 and remote_control:
            control = await http_connect(host, port)
            control_rtsp = RtspSession(control)
            await verify_connection(TRANSIENT_CREDENTIALS, control)
            reply = await exchange(control_rtsp, "SETUP", {"timingProtocol": "None", "isRemoteControlOnly": True})
            assert "eventPort" in reply
            await asyncio.open_connection(host, reply["eventPort"])
        await send(i)
    duration = len(frames) * FRAMES_PER_PACKET / SAMPLE_RATE
    if pause:
        # Pause in the middle and continue where it stopped
        middle = duration / 2
        await asyncio.sleep(max(0, start + middle - time.time()))
        await exchange(rtsp, "SETRATEANCHORTIME", {"rate": 0})
        await asyncio.sleep(1.0)
        resume_rtp = first_rtp + int(middle * SAMPLE_RATE)
        seconds, fraction = network_time(0.3)
        await exchange(rtsp, "SETRATEANCHORTIME", {"rate": 1, "rtpTime": resume_rtp, "networkTimeSecs": seconds,
                                                    "networkTimeFrac": fraction, "networkTimeTimelineID": 1})
        start += 1.3
    await asyncio.sleep(max(0, start + duration + 0.5 - time.time()))
    await exchange(rtsp, "TEARDOWN", {"streams": [{"type": 103}]})
    data.close()
    events.close()
    await rtsp.exchange("TEARDOWN")
    connection.close()
    timing.close()
    print("sent", len(frames), "packets")


asyncio.run(main())
