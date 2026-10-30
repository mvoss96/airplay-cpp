import asyncio, sys
import pyatv
from pyatv.conf import AppleTV, ManualService
from pyatv.const import Protocol
from pyatv.interface import MediaMetadata

async def main():
    loop = asyncio.get_running_loop()
    conf = AppleTV("127.0.0.1", "airplay-cpp test")
    props = dict(kv.split("=", 1) for kv in sys.argv[3:])
    conf.add_service(ManualService(sys.argv[2], Protocol.RAOP, 5000, props))
    atv = await pyatv.connect(conf, loop)
    try:
        await atv.audio.set_volume(40)
        await atv.stream.stream_file(sys.argv[1], metadata=MediaMetadata(title="Ramp", artist="pyatv", album="Interop"))
    finally:
        atv.close()

asyncio.run(main())
