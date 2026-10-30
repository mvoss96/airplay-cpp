import struct, sys, wave
frames = int(sys.argv[2]) if len(sys.argv) > 2 else 44100 * 6
with wave.open(sys.argv[1], "wb") as w:
    w.setnchannels(2); w.setsampwidth(2); w.setframerate(44100)
    data = bytearray()
    for i in range(frames):
        data += struct.pack("<hh", i & 0x7fff, ((i >> 15) & 0x3fff) | 0x4000)
    w.writeframes(bytes(data))
