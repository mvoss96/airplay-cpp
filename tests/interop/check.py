import struct, sys
data = open(sys.argv[1], "rb").read()
expected = int(sys.argv[2])
n = len(data) // 4
first = last = None; heard = 0; bad = 0; trims = 0
for i in range(n):
    l, r = struct.unpack_from("<hh", data, 4 * i)
    if l == 0 and r == 0:
        continue
    idx = (l & 0x7fff) | ((r & 0x3fff) << 15)
    heard += 1
    if last is not None:
        step = idx - last
        if step in (0, 2): trims += 1
        elif step != 1:
            bad += 1
            if bad < 5: print("jump", last, "->", idx)
    if first is None: first = idx
    last = idx
print(f"heard={heard} first={first} last={last} jumps={bad} trims={trims} expected={expected}")
ok = first is not None and first < 1000 and last >= expected - 8820 and bad == 0
print("INTEROP", "OK" if ok else "FAILED")
sys.exit(0 if ok else 1)
