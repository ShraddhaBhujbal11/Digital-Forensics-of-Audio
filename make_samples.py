"""Generate demo audio evidence: an original, a tampered copy, and a steganography copy."""
import os
import shutil
import wave

import numpy as np

SR = 44100
rng = np.random.default_rng(1)
os.makedirs("samples", exist_ok=True)


def voice(dur):
    t = np.arange(int(dur * SR)) / SR
    f0 = 120 + 30 * np.sin(2 * np.pi * 0.7 * t)
    phase = 2 * np.pi * np.cumsum(f0) / SR
    sig = sum(np.sin(k * phase) / k for k in range(1, 8))
    env = np.clip(np.sin(2 * np.pi * 1.2 * t), 0, None) ** 0.5   # speech-like bursts
    return 0.25 * sig * env


def to_int16(x):
    return np.clip(x * 32767, -32768, 32767).astype("<i2")


def write(path, ints):
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(ints.tobytes())


original = voice(8) + rng.normal(0, 0.002, 8 * SR)
write("samples/original.wav", to_int16(original))

# ---- tampered copy: (1) a chunk cut out, (2) digital silence, (3) segment from another "room"
t = original.copy()
a, b = int(5.7 * SR), int(7.7 * SR)
t[a:b] += rng.normal(0, 0.02, b - a)                # different noise floor
t[int(5.0 * SR):int(5.3 * SR)] = 0                                        # exact-zero gap
t = np.concatenate([t[:int(2.7 * SR)], t[int(3.4 * SR):]])               # deleted 0.7 s
write("samples/tampered.wav", to_int16(t))

# ---- steganography copy: message hidden in LSBs + a ZIP header appended after the audio
ints = to_int16(original).copy()
msg = b"SECRET: meet at 9pm, upload files to server 10.0.0.5"
bits = np.unpackbits(np.frombuffer(msg, np.uint8))
ints[:len(bits)] = (ints[:len(bits)] & ~1) | bits.astype("<i2")
write("samples/stego.wav", ints)
with open("samples/stego.wav", "ab") as f:
    f.write(b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + bytes(rng.integers(0, 256, 300, dtype=np.uint8)))

# ---- disguised file: WAV renamed as MP3
shutil.copy("samples/original.wav", "samples/disguised.mp3")
print("Samples written to ./samples")

# ---- ENF demo: 60 s recording with 50 Hz mains hum whose frequency wanders like a real grid
SR2 = 8000
n2 = 60 * SR2
t2 = np.arange(n2) / SR2
wander = 0.06 * np.sin(2 * np.pi * t2 / 45) + np.cumsum(rng.normal(0, 1, n2)) * 2e-6 * 0
walk = np.convolve(rng.normal(0, 1, n2 // 100), np.ones(200) / 200, "same") * 0.05
wander += np.interp(t2, np.linspace(0, 60, len(walk)), walk)
ph = 2 * np.pi * np.cumsum(50 + wander) / SR2
hum = 0.02 * np.sin(ph) + 0.012 * np.sin(2 * ph)
sp = np.zeros(n2)
for k in range(n2 // SR2):
    sp[k * SR2:(k + 1) * SR2] = 0
sp = np.clip(np.sin(2 * np.pi * 0.8 * t2), 0, None) ** 0.5 * np.sin(2 * np.pi * (200 + 60 * np.sin(2 * np.pi * 0.5 * t2)) * t2) * 0.1
enf_orig = hum + sp + rng.normal(0, 0.003, n2)
with wave.open("samples/enf_original.wav", "wb") as w:
    w.setnchannels(1); w.setsampwidth(2); w.setframerate(SR2)
    w.writeframes(to_int16(enf_orig).tobytes())
# edited: 24 s removed (12-36 s) and 6 s replaced by hum-free audio (20-26 s of the new timeline)
e = np.concatenate([enf_orig[:12 * SR2], enf_orig[36 * SR2:]])
e[20 * SR2:26 * SR2] = sp[20 * SR2:26 * SR2] + rng.normal(0, 0.003, 6 * SR2)
with wave.open("samples/enf_edited.wav", "wb") as w:
    w.setnchannels(1); w.setsampwidth(2); w.setframerate(SR2)
    w.writeframes(to_int16(e).tobytes())
print("ENF samples written")
