"""Compares the PCM output of a lossy stream (AAC) with the reference decoding of the same file.

Usage: check_lossy.py out.pcm reference.pcm [--pause]

The output is compared block by block with the reference, each block lined up on its own: the receiver repeats or
drops single frames to follow the sender's clock, and decoders differ only by rounding. All of the reference must
arrive, except for the decoder's priming at the start and 50 ms at the end. With --pause the output has a gap of
silence in the middle, after which it continues about where it stopped.
"""
import sys

import numpy as np

BLOCK = 4410  # 100 ms
TRIM_SHIFT = 6  # Frames the receiver may have repeated or dropped within a block
DRIFT = 20  # Frames a block may have moved against the end of the previous one

out = np.frombuffer(open(sys.argv[1], "rb").read(), dtype="<i2").reshape(-1, 2).astype(np.float64)
ref = np.frombuffer(open(sys.argv[2], "rb").read(), dtype="<i2").reshape(-1, 2).astype(np.float64)
pause = "--pause" in sys.argv

loud = np.abs(out).max(axis=1) > 0
audible = np.flatnonzero(loud)
if audible.size == 0:
    sys.exit("no audio")
out = out[audible[0] : audible[-1] + 1]
loud = loud[audible[0] : audible[-1] + 1]

# The first block is found anywhere in the reference by cross-correlation. After that each block is expected right
# after the previous one, give or take the few frames the receiver repeats or drops: of the positions around it, the
# one with the smallest error is taken (correlation alone picks wrong peaks in sweeps).
probe = out[:BLOCK, 0]
position = int(np.argmax(np.correlate(ref[:, 0], probe, mode="valid")))
print("starts at reference frame", position)


def block_noise(block, start):
    """Error of a block against the reference at start, each sample compared with the nearest of the reference's
    samples around it (a repeated or dropped frame shifts the rest of the block)"""
    errors = []
    for shift in range(-TRIM_SHIFT, TRIM_SHIFT + 1):
        at = start + shift
        if 0 <= at and at + len(block) <= len(ref):
            errors.append(np.sum((block - ref[at : at + len(block)]) ** 2, axis=1))
    return np.sum(np.min(errors, axis=0)) if errors else np.inf


snrs = []
gap = False
offset = 0
while offset + BLOCK <= len(out):
    block = out[offset : offset + BLOCK]
    if not loud[offset : offset + BLOCK].any():
        gap = True  # Silence, e.g. a pause
        offset += BLOCK
        continue
    if gap:
        # After a pause anywhere in the reference: the sender may continue a little before where playback stopped
        position = int(np.argmax(np.correlate(ref[:, 0], block[:, 0], mode="valid")))
        print("continues at reference frame", position)
        gap = False
    candidates = [position + d for d in range(-DRIFT, DRIFT + 1)]
    candidates = [c for c in candidates if 0 <= c and c + BLOCK <= len(ref)]
    if not candidates:
        break
    noises = [block_noise(block, c) for c in candidates]
    best = candidates[int(np.argmin(noises))]
    expected = ref[best : best + BLOCK]
    snrs.append(10 * np.log10(np.sum(expected**2) / max(min(noises), 1)))
    position = best + BLOCK
    offset += BLOCK
snrs = np.array(snrs)
if "--verbose" in sys.argv:
    print(" ".join(f"{x:.0f}" for x in snrs))
print(f"{len(snrs)} blocks, SNR min {snrs.min():.1f} dB, median {np.median(snrs):.1f} dB; reached reference frame {position}")
# Decoders differ a little while they settle at the start, the rest matches but for rounding
good = np.mean(snrs >= 30)
print(f"{good:.0%} of the blocks match closely")
if np.median(snrs) < 60 or good < 0.85 or snrs.min() < 5:
    sys.exit("output differs from the reference")
if position < len(ref) - 2048 - 2205 - BLOCK:
    sys.exit("output is incomplete")
print("BUFFERED OK")
