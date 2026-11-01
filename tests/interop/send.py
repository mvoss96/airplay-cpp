import asyncio, os, sys
import pyatv
from pyatv.conf import AppleTV, ManualService
from pyatv.const import Protocol
from pyatv.interface import MediaMetadata

def record_before_stream_setup():
    """Sends RECORD before the stream SETUP, as iOS does"""
    from pyatv.protocols.raop.protocols import airplayv2
    from pyatv.support.rtsp import RtspSession

    original_record = RtspSession.record
    recorded = set()

    async def setup(self, timing_server_port, control_client_port):
        await self._setup_base(timing_server_port)
        await original_record(self.rtsp)
        recorded.add(self.rtsp)
        await self.setup_audio_stream(control_client_port)

    async def record(self, *args, **kwargs):
        if self in recorded:  # Already sent
            return None
        return await original_record(self, *args, **kwargs)

    airplayv2.AirPlayV2.setup = setup
    RtspSession.record = record


def stream_without_key(mode):
    """Leaves the key out of the stream SETUP, as iOS does for realtime streams. The audio is then sent
    unencrypted (mode "none"), encrypted with a zero key (mode "zero") or, as iOS does, with the key of a
    buffered stream offered before (mode "earlier"), which the receiver turns down."""
    from pyatv.protocols.raop.protocols import airplayv2
    from pyatv.support.chacha20 import Chacha20Cipher8byteNonce

    original = airplayv2.AirPlayV2.setup_audio_stream

    async def setup_audio_stream(self, control_client_port):
        key = bytes(32)
        if mode == "earlier":
            key, _ = self._verifier.encryption_keys(
                airplayv2.EVENTS_SALT, airplayv2.EVENTS_WRITE_INFO, airplayv2.EVENTS_READ_INFO
            )
            key = key[0:32]
            # 48 kHz AAC, which the receiver turns down
            offer = {"streams": [{"type": 103, "ct": 4, "spf": 1024, "audioFormat": 0x1000000, "shk": key}]}
            response = await self.rtsp.exchange("SETUP", body=offer, allow_error=True)
            assert response.code != 200, "The buffered stream should be turned down"
        original_setup = self.rtsp.setup

        async def setup(headers=None, body=None):
            if isinstance(body, dict):
                for stream in body.get("streams", []):
                    stream.pop("shk", None)
            return await original_setup(headers=headers, body=body)

        self.rtsp.setup = setup
        try:
            await original(self, control_client_port)
        finally:
            self.rtsp.setup = original_setup
        self._cipher = None if mode == "none" else Chacha20Cipher8byteNonce(key, key)

    airplayv2.AirPlayV2.setup_audio_stream = setup_audio_stream


async def main():
    loop = asyncio.get_running_loop()
    conf = AppleTV("127.0.0.1", "airplay-cpp test")
    props = dict(kv.split("=", 1) for kv in sys.argv[3:])
    # AIRPLAY_PASSWORD makes the sender log in with RTSP Digest authentication
    password = os.environ.get("AIRPLAY_PASSWORD")
    conf.add_service(
        ManualService(sys.argv[2], Protocol.RAOP, 5000, props, password=password, requires_password=bool(password))
    )
    atv = await pyatv.connect(conf, loop)
    try:
        await atv.audio.set_volume(40)
        # Stand-in for a cover image: the receiver only passes the bytes on
        artwork = bytes([0xFF, 0xD8]) + bytes(i * 7 % 256 for i in range(30000))
        with open("artwork.bin", "wb") as f:
            f.write(artwork)
        metadata = MediaMetadata(title="Ramp", artist="pyatv", album="Interop", artwork=artwork)
        await atv.stream.stream_file(sys.argv[1], metadata=metadata)
    finally:
        atv.close()

if os.environ.get("AUDIO_KEY") in ("none", "zero", "earlier"):
    stream_without_key(os.environ["AUDIO_KEY"])
if os.environ.get("RECORD_FIRST") == "1":
    record_before_stream_setup()
asyncio.run(main())
