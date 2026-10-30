"""Checks the PCM output of a stream of make_wav.py's test signal: every frame carries its own index.

Usage: check.py out.pcm <frames sent> [--max-skipped N] [--allow-lost-packets] [--max-start N]

Steps of 0 or 2 are single frames that the receiver repeated or dropped to follow the sender's clock. Larger
steps forward are audio that was lost; with --max-skipped up to N frames may be lost in total (some senders
drop samples themselves). With --allow-lost-packets, gaps of whole packets (352 frames, give or take the single
frames above) are counted as lost packets instead: the receiver plays silence for packets that never arrive,
e.g. when the sender does not retransmit. Steps backward are never allowed. --max-start is the latest first
frame (default 1000): when the sync packets at the start are lost, the first packets are already due once the
sender's timeline is known and cannot be played in sync.
"""
import struct
import sys

data = open(sys.argv[1], "rb").read()
expected = int(sys.argv[2])
max_skipped = int(sys.argv[sys.argv.index("--max-skipped") + 1]) if "--max-skipped" in sys.argv else 0
allow_lost_packets = "--allow-lost-packets" in sys.argv
max_start = int(sys.argv[sys.argv.index("--max-start") + 1]) if "--max-start" in sys.argv else 1000
FRAMES_PER_PACKET = 352

first = last = None
heard = trims = skipped = backward = lost_packets = 0
for i in range(len(data) // 4):
    left, right = struct.unpack_from("<hh", data, 4 * i)
    if left == 0 and right == 0:
        continue
    index = (left & 0x7FFF) | ((right & 0x3FFF) << 15)
    heard += 1
    if last is not None:
        step = index - last
        if step in (0, 2):
            trims += 1
        elif step < 0:
            backward += 1
            print("backward", last, "->", index)
        elif step > 2:
            gap = step - 1
            packets = round(gap / FRAMES_PER_PACKET)
            if allow_lost_packets and packets > 0 and abs(gap - packets * FRAMES_PER_PACKET) <= 2:
                lost_packets += packets
            else:
                skipped += gap
                print("skip", last, "->", index)
    if first is None:
        first = index
    last = index

print(f"heard={heard} first={first} last={last} trims={trims} skipped={skipped} lost_packets={lost_packets} "
      f"backward={backward} sent={expected}")
# The sender ends the session right after its last packet, so up to 200 ms may be cut off at the end
ok = (first is not None and first < max_start and last >= expected - 8820 and backward == 0
      and skipped <= max_skipped)
print("INTEROP", "OK" if ok else "FAILED")
sys.exit(0 if ok else 1)
