"""AirPlay 2 buffered audio sender: AAC over TCP, as iOS streams most apps.

Pairing and the encrypted RTSP connection come from pyatv; the buffered stream (stream type 103), which pyatv
cannot send, is done here.

Usage: send_buffered.py <host> <port> <file.aac (ADTS)> [--pause] [--remote-control] [--second-session] [--handover]
                        [--takeover-and-back]
       send_buffered.py <host> <port> <file.pcm (16-bit stereo)> --alac [--paced]

--alac sends the PCM file as ALAC (uncompressed ALAC packets of 352 frames), as Music Assistant does when the receiver
offers PTP timing. --paced also sends it as Music Assistant does: its RTP header (a 16-bit sequence number, the
payload type in the byte above), playback 0.4 s after the anchor is sent, the audio following it at most 1.75 s
ahead of playback. --ma-resume (with --paced) then pauses and resumes halfway as Music Assistant does on a start
command: a rate 0 anchor, FLUSHBUFFERED, and a new anchor on a timeline moved past what was sent. --ma-pause (with
--paced) pauses for 11 s without a flush and resumes where the sender's timeline went on in the meantime, as Music
Assistant did: the audio held from before the pause is then 11 s late.

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


def alac_packets(path):
    """Uncompressed ALAC packets of the raw 16-bit stereo PCM in path: a channel pair element with the escape flag,
    the samples, then the end element"""
    data = open(path, "rb").read()
    packets = []
    for offset in range(0, len(data) - 3, FRAMES_PER_PACKET * 4):
        chunk = data[offset : offset + FRAMES_PER_PACKET * 4]
        frames = len(chunk) // 4
        partial = frames != FRAMES_PER_PACKET
        bits = (1 << 4 | 0) << 12  # Channel pair element (type 1), instance 0, 12 unused bits
        bits = (bits << 4) | (int(partial) << 3) | 1  # Partial frame, no shift, escape (uncompressed)
        width = 3 + 4 + 12 + 4
        if partial:
            bits = (bits << 32) | frames
            width += 32
        for (sample,) in struct.iter_unpack("<h", chunk[: frames * 4]):
            bits = (bits << 16) | (sample & 0xFFFF)
            width += 16
        bits = (bits << 3) | 7  # End element
        width += 3
        padding = -width % 8
        packets.append((bits << padding).to_bytes((width + padding) // 8, "big"))
    return packets


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
    global FRAMES_PER_PACKET
    host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    alac = "--alac" in sys.argv
    paced = "--paced" in sys.argv
    paced_ahead = float(os.environ.get("PACED_AHEAD", "1.75"))  # Less for a sender that falls behind
    paced_stall = float(os.environ.get("PACED_STALL", "0"))
    ma_resume = paced and "--ma-resume" in sys.argv
    ma_pause = paced and "--ma-pause" in sys.argv
    if alac:
        FRAMES_PER_PACKET = 352
    pause = "--pause" in sys.argv
    remote_control = "--remote-control" in sys.argv
    # As macOS: it answers no remote control, so the receiver answers a controller itself
    macos = "--macos" in sys.argv
    second_session = "--second-session" in sys.argv or "--handover" in sys.argv
    handover = "--handover" in sys.argv
    takeover = "--takeover-and-back" in sys.argv
    frames = alac_packets(path) if alac else read_adts(path)
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
             "timingProtocol": "NTP", "name": "buffered test", "model": "Mac17,8" if macos else "iPhone17,3",
             "osName": "macOS" if macos else "iPhone OS",
             # As iOS sends it: the group it plays the receiver in
             "groupUUID": "2F41DCA0-C513-4478-97E6-12AA296E0B08", "groupContainsGroupLeader": False},
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
            {"streams": [{"type": 103, "ct": 2 if alac else 4, "audioFormat": 0x40000 if alac else 0x400000,
                          "spf": FRAMES_PER_PACKET, "shk": key,
                          "audioMode": "default", "isMedia": True, "supportsDynamicStreamID": True}]},
        )
        print("buffer size", stream["streams"][0].get("audioBufferSize"))
        _, data = await asyncio.open_connection(host, stream["streams"][0]["dataPort"], local_addr=(source, 0))
        return ChaCha20Poly1305(key), data

    connection, rtsp, events, event_reader = await open_session()
    cipher, data = await open_stream(rtsp)
    ssrc = 0x12345678
    first_rtp = 1000000
    # Music Assistant's header: the sequence number starts anywhere (here just before it wraps), the marker is set on
    # the first packet of a timeline; its timeline moves on a resume
    ma = {"seq": 0xFF00, "marker": True, "shift": 0, "packets": 0}

    def rtp_of(index):
        return (first_rtp + index * FRAMES_PER_PACKET + ma["shift"]) & 0xFFFFFFFF

    async def send(index, audio=None, stream=None):
        stream_cipher, stream_data = stream or (cipher, data)
        rtp = rtp_of(index)
        if paced:
            header = struct.pack(">BBHII", 0x80, 0xE7 if ma["marker"] else 0x67, ma["seq"] & 0xFFFF, rtp, ssrc)
            ma["seq"] += 1
            ma["marker"] = False
        else:
            header = struct.pack(">BBHII", 0x80, 0x60, 0, rtp, ssrc)
            header = header[:1] + struct.pack(">I", index + 1)[1:] + header[4:]  # 24-bit sequence number
        nonce = struct.pack("<Q", ma["packets"])
        ma["packets"] += 1
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

    async def received(reader):
        """How much came on an event connection (encrypted, so only how much)"""
        await asyncio.sleep(0.3)
        return len(await asyncio.wait_for(reader.read(65536), 3))

    async def relay_remote_control(control_rtsp, control_reader):
        """As an iPad controls the playing sender through a speaker: a remote control stream (type 130) whose
        MediaRemote messages the receiver passes on in both directions"""
        reply = await exchange(control_rtsp, "SETUP", {"streams": [{
            "type": 130, "controlType": 1, "clientUUID": str(uuid.uuid4()).upper(),
            "clientTypeUUID": "1910A70F-DBC0-4242-AF95-115DB30604E1"}]})
        stream_id = reply["streams"][0]["streamID"]
        assert await received(event_reader), "the sender heard nothing of the controller"
        # Another app of the same device: a stream of its own, which ends on its own
        reply = await exchange(control_rtsp, "SETUP", {"streams": [{
            "type": 130, "controlType": 1, "clientUUID": str(uuid.uuid4()).upper(),
            "clientTypeUUID": "1910A70F-DBC0-4242-AF95-115DB30604E1"}]})
        other_id = reply["streams"][0]["streamID"]
        assert other_id != stream_id, "two streams with one number"
        assert await received(event_reader), "the sender heard nothing of the second stream"
        await control_rtsp.exchange("TEARDOWN", content_type="application/x-apple-binary-plist",
                                    body=plistlib.dumps({"streams": [{"streamID": other_id, "type": 130}]},
                                                        fmt=plistlib.FMT_BINARY))
        assert await received(event_reader), "the sender heard nothing of the second stream's end"
        response = await control_rtsp.exchange("POST", uri="/command", content_type="application/octet-stream",
                                               body=bytes(range(256)) * 3)  # Larger than one frame of 512
        assert response.code == 200
        assert await received(event_reader), "the controller's message did not reach the sender"
        response = await rtsp.exchange("POST", uri="/command", content_type="application/x-apple-binary-plist",
                                       headers={"X-Apple-StreamID": stream_id},
                                       body=plistlib.dumps({"params": {"data": b"answer"}}, fmt=plistlib.FMT_BINARY))
        assert response.code == 200
        assert await received(control_reader), "the sender's answer did not reach the controller"
        # Now playing details with cover art: larger than the receiver's buffer, passed on as they come
        large = plistlib.dumps({"params": {"data": bytes(range(256)) * 14}}, fmt=plistlib.FMT_BINARY)
        response = await rtsp.exchange("POST", uri="/command", content_type="application/x-apple-binary-plist",
                                       headers={"X-Apple-StreamID": stream_id}, body=large)
        assert response.code == 200
        assert await received(control_reader) > len(large), "the large answer did not reach the controller whole"
        await control_rtsp.exchange("TEARDOWN", content_type="application/x-apple-binary-plist",
                                    body=plistlib.dumps({}, fmt=plistlib.FMT_BINARY))
        assert await received(event_reader), "the sender heard nothing of the end"

    async def answered_remote_control(control_rtsp, control_reader):
        """As an iPad's Home app tile while a Mac plays: the receiver answers its MediaRemote messages and passes
        its commands on to the sender"""
        from pyatv.protocols.mrp import messages, protobuf
        from pyatv.support.variant import write_variant

        def mrp(*protos):
            data = b"".join(write_variant(len(p.SerializeToString())) + p.SerializeToString() for p in protos)
            return plistlib.dumps({"params": {"data": data}}, fmt=plistlib.FMT_BINARY)

        reply = await exchange(control_rtsp, "SETUP", {"streams": [{
            "type": 130, "controlType": 1, "clientUUID": str(uuid.uuid4()).upper(),
            "clientTypeUUID": "1910A70F-DBC0-4242-AF95-115DB30604E1"}]})
        stream_id = reply["streams"][0]["streamID"]
        assert await received(event_reader), "the sender heard nothing of the controller"
        info = messages.create(protobuf.DEVICE_INFO_MESSAGE, identifier=str(uuid.uuid4()).upper())
        protobuf.extract_inner(info).name = "iPad"
        for body in (mrp(info), mrp(messages.set_connection_state(), messages.client_updates_config()),
                     mrp(messages.playback_queue_request(0))):
            response = await control_rtsp.exchange("POST", uri="/command",
                                                   content_type="application/x-apple-binary-plist",
                                                   headers={"X-Apple-StreamID": stream_id}, body=body)
            assert response.code == 200
        assert await received(control_reader) > 300, "the controller got no answer"
        pause = messages.command(2)  # Pause
        response = await control_rtsp.exchange("POST", uri="/command", content_type="application/x-apple-binary-plist",
                                               headers={"X-Apple-StreamID": stream_id}, body=mrp(pause))
        assert response.code == 200
        assert await received(control_reader), "the command got no result"
        await control_rtsp.exchange("TEARDOWN", content_type="application/x-apple-binary-plist",
                                    body=plistlib.dumps({}, fmt=plistlib.FMT_BINARY))

    # Some audio ahead, then playback starts half a second from now while the rest follows as the buffer drains
    ahead = 0 if paced else min(20, len(frames))
    for i in range(ahead):
        await send(i)
    lead = 0.4 if paced else 0.5
    seconds, fraction = network_time(lead)
    await exchange(rtsp, "SETRATEANCHORTIME", {"rate": 1, "rtpTime": first_rtp, "networkTimeSecs": seconds,
                                                "networkTimeFrac": fraction, "networkTimeTimelineID": 1})
    start = time.time() + lead
    i = ahead
    resumed = False
    while i < len(frames):
        if (ma_resume or ma_pause) and not resumed and i == len(frames) // 2:
            resumed = True
            audible = int((time.time() - start) * SAMPLE_RATE / FRAMES_PER_PACKET)
            seconds, fraction = network_time(0)
            await exchange(rtsp, "SETRATEANCHORTIME", {"rate": 0, "rtpTime": rtp_of(audible), "networkTimeSecs": seconds,
                                                        "networkTimeFrac": fraction, "networkTimeTimelineID": 1})
            if ma_pause:
                await asyncio.sleep(11.0)
                # The audio goes on after what was sent, 11 s further on the timeline than where it was paused
                ma["shift"] += 11 * SAMPLE_RATE - (i - audible) * FRAMES_PER_PACKET
                seconds, fraction = network_time(lead)
                await exchange(rtsp, "SETRATEANCHORTIME", {"rate": 1, "rtpTime": rtp_of(i), "networkTimeSecs": seconds,
                                                            "networkTimeFrac": fraction, "networkTimeTimelineID": 1})
                start = time.time() + lead - i * FRAMES_PER_PACKET / SAMPLE_RATE
                continue
            await exchange(rtsp, "FLUSHBUFFERED", {"flushUntilSeq": ma["seq"] & 0xFFFF, "flushUntilTS": rtp_of(i)})
            await asyncio.sleep(1.0)
            # The audio from where it was paused follows on a timeline past all that was sent (and 100 ms more)
            ma["shift"] += (i - audible) * FRAMES_PER_PACKET + SAMPLE_RATE // 10
            ma["marker"] = True
            i = audible
            seconds, fraction = network_time(lead)
            await exchange(rtsp, "SETRATEANCHORTIME", {"rate": 1, "rtpTime": rtp_of(i), "networkTimeSecs": seconds,
                                                        "networkTimeFrac": fraction, "networkTimeTimelineID": 1})
            start = time.time() + lead - i * FRAMES_PER_PACKET / SAMPLE_RATE
            continue
        if paced:
            await asyncio.sleep(max(0.001, start + i * FRAMES_PER_PACKET / SAMPLE_RATE - paced_ahead - time.time()))
            if paced_stall and i % 250 == 125:
                await asyncio.sleep(paced_stall)  # A hold-up in the sender: what follows comes late
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
            # A controller on another device (an iPad), which then controls this sender through the receiver
            _, control = await loop.create_connection(HttpConnection, host, port, local_addr=("127.0.0.2", 0))
            control_rtsp = RtspSession(control)
            await verify_connection(TRANSIENT_CREDENTIALS, control)
            reply = await exchange(control_rtsp, "SETUP", {"timingProtocol": "None", "isRemoteControlOnly": True})
            assert "eventPort" in reply
            control_reader, _ = await asyncio.open_connection(host, reply["eventPort"], local_addr=("127.0.0.2", 0))
            await exchange(control_rtsp, "RECORD")  # As the Home app does when it adds the receiver
            if macos:
                await answered_remote_control(control_rtsp, control_reader)
            else:
                await relay_remote_control(control_rtsp, control_reader)
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
