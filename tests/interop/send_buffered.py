"""AirPlay 2 buffered audio sender: AAC over TCP, as iOS streams most apps.

Pairing and the encrypted RTSP connection come from pyatv; the buffered stream (stream type 103), which pyatv
cannot send, is done here.

Usage: send_buffered.py <host> <port> <file.aac (ADTS)> [--pause] [--remote-control] [--second-session] [--handover]
                        [--takeover-and-back]

--remote-control opens a second session during playback, only to control it, as iOS does; playback goes on.
--second-session sets up a second audio session during playback without a stream, as iOS sometimes does; playback
goes on. --handover lets that session take over: it sets up its own stream and sends the rest of the file.
--takeover-and-back lets another device (from 127.0.0.2) take over for a while: the first sender must be paused on
its event connection and stay connected, then takes over again with a new stream, as iOS does when play is pressed.
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
from pyatv.support.http import HttpConnection, http_connect
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
    second_session = "--second-session" in sys.argv or "--handover" in sys.argv
    handover = "--handover" in sys.argv
    takeover = "--takeover-and-back" in sys.argv
    frames = read_adts(path)
    loop = asyncio.get_running_loop()

    timing, _ = await loop.create_datagram_endpoint(TimingServer, local_addr=("127.0.0.1", 0))
    timing_port = timing.get_extra_info("socket").getsockname()[1]

    async def open_session(source="127.0.0.1", session_timing_port=None):
        """Pairs and sets up a session with its event connection, then RECORD, as iOS does"""
        _, connection = await loop.create_connection(HttpConnection, host, port, local_addr=(source, 0))
        rtsp = RtspSession(connection)
        await verify_connection(TRANSIENT_CREDENTIALS, connection)  # Transient pairing, then encrypted
        session = await exchange(
            rtsp,
            "SETUP",
            {"deviceID": "AA:BB:CC:DD:EE:FF" if source == "127.0.0.1" else "AA:BB:CC:DD:EE:00",
             "sessionUUID": str(uuid.uuid4()).upper(), "timingPort": session_timing_port or timing_port,
             "timingProtocol": "NTP", "name": "buffered test", "model": "iPhone17,3"},
        )
        event_reader, events = await asyncio.open_connection(host, session["eventPort"], local_addr=(source, 0))
        await asyncio.sleep(0.2)
        await exchange(rtsp, "RECORD")
        return connection, rtsp, events, event_reader

    async def open_stream(rtsp, source="127.0.0.1"):
        key = os.urandom(32)
        stream = await exchange(
            rtsp,
            "SETUP",
            {"streams": [{"type": 103, "ct": 4, "audioFormat": 0x400000, "spf": FRAMES_PER_PACKET, "shk": key,
                          "audioMode": "default", "isMedia": True, "supportsDynamicStreamID": True}]},
        )
        print("buffer size", stream["streams"][0].get("audioBufferSize"))
        _, data = await asyncio.open_connection(host, stream["streams"][0]["dataPort"], local_addr=(source, 0))
        return ChaCha20Poly1305(key), data

    connection, rtsp, events, event_reader = await open_session()
    cipher, data = await open_stream(rtsp)
    ssrc = 0x12345678
    first_rtp = 1000000

    async def send(index, audio=None, stream=None):
        stream_cipher, stream_data = stream or (cipher, data)
        rtp = first_rtp + index * FRAMES_PER_PACKET
        header = struct.pack(">BBHII", 0x80, 0x60, 0, rtp, ssrc)
        header = header[:1] + struct.pack(">I", index + 1)[1:] + header[4:]  # 24-bit sequence number
        nonce = struct.pack("<Q", index)
        sealed = stream_cipher.encrypt(b"\0\0\0\0" + nonce, frames[index] if audio is None else audio, header[4:12])
        packet = header + sealed + nonce
        stream_data.write(struct.pack(">H", len(packet) + 2) + packet)
        await stream_data.drain()

    async def anchor(session_rtsp, index, delay):
        seconds, fraction = network_time(delay)
        await exchange(session_rtsp, "SETRATEANCHORTIME", {"rate": 1, "rtpTime": first_rtp + index * FRAMES_PER_PACKET,
                                                            "networkTimeSecs": seconds, "networkTimeFrac": fraction,
                                                            "networkTimeTimelineID": 1})
        return time.time() + delay - index * FRAMES_PER_PACKET / SAMPLE_RATE

    async def take_over_and_back(i):
        """Another device plays frames i to i + 100, then this sender plays on with a new stream"""
        await asyncio.sleep(max(0, start + i * FRAMES_PER_PACKET / SAMPLE_RATE - time.time()))  # This one plays first
        other_timing, _ = await loop.create_datagram_endpoint(TimingServer, local_addr=("127.0.0.2", 0))
        other_timing_port = other_timing.get_extra_info("socket").getsockname()[1]
        other_connection, other_rtsp, other_events, _ = await open_session("127.0.0.2", other_timing_port)
        other_stream = await open_stream(other_rtsp, "127.0.0.2")
        # This sender is paused on its event connection and stays connected
        paused = await asyncio.wait_for(event_reader.read(1), 3)
        assert paused, "no request on the event connection"
        # As iOS does on that pause: its stream ends, the connection stays
        await exchange(rtsp, "TEARDOWN", {"streams": [{"type": 103}]})
        data.close()
        for j in range(i, i + 20):
            await send(j, stream=other_stream)
        other_start = await anchor(other_rtsp, i, 0.3)
        for j in range(i + 20, i + 100):
            await asyncio.sleep(max(0, other_start + (j - 40) * FRAMES_PER_PACKET / SAMPLE_RATE - time.time()))
            await send(j, stream=other_stream)
        await asyncio.sleep(max(0, other_start + (i + 100) * FRAMES_PER_PACKET / SAMPLE_RATE - time.time()))
        # Play is pressed here: a new stream takes over again while the other device is still connected
        new_stream = await open_stream(rtsp)
        for j in range(i + 100, i + 120):
            await send(j, stream=new_stream)
        new_start = await anchor(rtsp, i + 100, 0.3)
        other_stream[1].close()
        other_events.close()
        other_connection.close()
        other_timing.close()
        return new_stream, new_start, i + 120

    # Some audio ahead, then playback starts half a second from now while the rest follows as the buffer drains
    for i in range(min(20, len(frames))):
        await send(i)
    seconds, fraction = network_time(0.5)
    await exchange(rtsp, "SETRATEANCHORTIME", {"rate": 1, "rtpTime": first_rtp, "networkTimeSecs": seconds,
                                                "networkTimeFrac": fraction, "networkTimeTimelineID": 1})
    start = time.time() + 0.5
    i = 20
    while i < len(frames):
        if i == 140 and takeover:
            (cipher, data), start, i = await take_over_and_back(i)
            continue
        if i == 100:
            await send(i, b"")  # As iOS sends after a flush: no audio, to be skipped
        if i == 140 and second_session:
            second_connection, second_rtsp, second_events, _ = await open_session()
            if handover:
                # The second session takes over with its own stream from here on
                cipher, data = await open_stream(second_rtsp)
                connection, rtsp = second_connection, second_rtsp
                seconds, fraction = network_time(0.3)
                await exchange(rtsp, "SETRATEANCHORTIME", {"rate": 1, "rtpTime": first_rtp + i * FRAMES_PER_PACKET,
                                                            "networkTimeSecs": seconds, "networkTimeFrac": fraction,
                                                            "networkTimeTimelineID": 1})
                start = time.time() + 0.3 - i * FRAMES_PER_PACKET / SAMPLE_RATE
        if i == 120 and remote_control:
            control = await http_connect(host, port)
            control_rtsp = RtspSession(control)
            await verify_connection(TRANSIENT_CREDENTIALS, control)
            reply = await exchange(control_rtsp, "SETUP", {"timingProtocol": "None", "isRemoteControlOnly": True})
            assert "eventPort" in reply
            await asyncio.open_connection(host, reply["eventPort"])
        await send(i)
        i += 1
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
