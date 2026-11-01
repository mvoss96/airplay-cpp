"""Writes a test signal for lossy codecs: two sweeps with a little noise, so that any part of it can be found again.

Usage: make_signal.py out.wav <seconds>
"""
import sys
import wave

import numpy as np

rate = 44100
frames = int(float(sys.argv[2]) * rate)
t = np.arange(frames) / rate
rng = np.random.default_rng(1)
left = 0.4 * np.sin(2 * np.pi * (200 + 300 * t) * t) * (0.6 + 0.4 * np.sin(2 * np.pi * 0.7 * t))
right = 0.4 * np.sin(2 * np.pi * (1500 - 150 * t) * t)
pcm = np.stack([left, right], 1) + 0.05 * rng.standard_normal((frames, 2))
with wave.open(sys.argv[1], "wb") as out:
    out.setnchannels(2)
    out.setsampwidth(2)
    out.setframerate(rate)
    out.writeframes((pcm * 32767).astype("<i2").tobytes())
