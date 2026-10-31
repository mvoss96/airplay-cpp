import asyncio, os, sys
import pyatv
from pyatv.conf import AppleTV, ManualService
from pyatv.const import Protocol
from pyatv.interface import MediaMetadata

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

asyncio.run(main())
