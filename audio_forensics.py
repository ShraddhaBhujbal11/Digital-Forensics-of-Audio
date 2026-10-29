#!/usr/bin/env python3
"""
AudioForensics - a digital forensics toolkit for audio evidence.

Modules
  1. Evidence integrity   : MD5 / SHA-1 / SHA-256 before and after analysis, timestamps
  2. Format verification  : magic-byte detection vs. file extension
  3. Container analysis   : RIFF/WAV chunk walk, header-vs-file size, LIST/INFO metadata,
                            editing-software traces, appended (trailing) data
  4. Tamper detection     : digital-silence gaps, waveform discontinuities (splice points),
                            background-noise-floor changes, spectral cut-off (transcoding)
  5. Hidden data          : embedded file signatures, LSB steganography check
  6. Reporting            : JSON + HTML report with plots
  7. Compare              : sample-level comparison of two recordings

NOTE: results are *indicators* for an examiner to review, not proof of tampering.

Usage
  python audio_forensics.py analyze evidence.wav --case CASE-01 --examiner "Your Name" --out report_dir
  python audio_forensics.py compare original.wav suspect.wav
"""
import argparse
import base64
import datetime as dt
import hashlib
import html
import json
import os
import struct
import sys

import numpy as np
from scipy import signal
from scipy.ndimage import uniform_filter1d

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

VERSION = "1.0"
SEV_WEIGHT = {"info": 0, "low": 1, "medium": 3, "high": 5}

EXT_FORMAT = {".wav": "WAV", ".wave": "WAV", ".mp3": "MP3", ".flac": "FLAC", ".ogg": "OGG",
              ".m4a": "M4A/MP4", ".mp4": "M4A/MP4", ".aif": "AIFF", ".aiff": "AIFF"}

KNOWN_CHUNKS = {"fmt ", "data", "LIST", "fact", "cue ", "bext", "JUNK", "junk", "PAD ", "id3 ",
                "ID3 ", "smpl", "inst", "iXML", "_PMX", "minf", "plst", "PEAK", "levl", "DISP"}

EDITOR_HINTS = ["audacity", "adobe", "sound forge", "ocenaudio", "wavepad", "goldwave", "ffmpeg",
                "lavf", "reaper", "pro tools", "logic", "garageband", "cool edit", "nch", "sox"]

# signatures of files that might be hidden inside an audio file
EMBED_SIGS = {   # long signatures only, so random audio samples do not trigger false hits
    b"PK\x03\x04\x14\x00": "ZIP/Office archive", b"PK\x03\x04\x0a\x00": "ZIP archive",
    b"%PDF-1.": "PDF document", b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff\xe0\x00\x10JFIF": "JPEG image", b"GIF89a": "GIF image", b"GIF87a": "GIF image",
    b"Rar!\x1a\x07": "RAR archive", b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
    b"\x7fELF\x02\x01\x01": "ELF executable", b"\x7fELF\x01\x01\x01": "ELF executable",
    b"MZ\x90\x00\x03\x00\x00\x00": "Windows executable (PE)", b"SQLite format 3": "SQLite database",
}


# --------------------------------------------------------------------------- helpers
class Findings:
    def __init__(self):
        self.items = []

    def add(self, severity, category, title, detail="", time_s=None):
        self.items.append({"severity": severity, "category": category, "title": title,
                           "detail": detail, "time_s": None if time_s is None else round(float(time_s), 4)})

    def score(self):
        return sum(SEV_WEIGHT[i["severity"]] for i in self.items)

    def verdict(self):
        s = self.score()
        if s == 0:
            return "NO INDICATORS FOUND"
        if s < 3:
            return "LOW SUSPICION"
        if s < 8:
            return "MEDIUM SUSPICION"
        return "HIGH SUSPICION"


def _js(o):
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.floating):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    if isinstance(o, bytes):
        return o.hex()
    return str(o)


def ts(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat()


def hashes(data):
    return {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}


def runs(mask):
    """Return (start, end) index pairs (end exclusive) of True runs in a boolean array."""
    m = np.concatenate(([0], mask.astype(np.int8), [0]))
    d = np.diff(m)
    return list(zip(np.where(d == 1)[0], np.where(d == -1)[0]))


def db(v):
    return 20 * np.log10(np.maximum(v, 1e-6))


# --------------------------------------------------------------------------- format / container
def identify_format(data):
    if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return "WAV"
    if data[:4] == b"fLaC":
        return "FLAC"
    if data[:4] == b"OggS":
        return "OGG"
    if data[:3] == b"ID3" or (len(data) > 1 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0):
        return "MP3"
    if data[4:8] == b"ftyp":
        return "M4A/MP4"
    if data[:4] == b"FORM" and data[8:12] in (b"AIFF", b"AIFC"):
        return "AIFF"
    return "UNKNOWN"


def parse_riff(data):
    info = {"is_riff": False, "chunks": [], "info_tags": {}, "trailing_bytes": 0,
            "declared_size": None, "actual_size": len(data), "fmt": None, "data_range": None}
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return info
    info["is_riff"] = True
    info["declared_size"] = struct.unpack("<I", data[4:8])[0] + 8
    pos = 12
    truncated = False
    while pos + 8 <= len(data):
        raw_id = data[pos:pos + 4]
        if not all(32 <= b < 127 for b in raw_id):      # not a valid chunk id -> appended data
            break
        cid = raw_id.decode("latin-1")
        size = struct.unpack("<I", data[pos + 4:pos + 8])[0]
        start, end = pos + 8, pos + 8 + size
        trunc = end > len(data)
        info["chunks"].append({"id": cid, "offset": pos, "size": size, "truncated": trunc})
        if cid == "fmt " and size >= 16:
            tag, ch, rate, _, _, bits = struct.unpack("<HHIIHH", data[start:start + 16])
            if tag == 0xFFFE and size >= 26:
                tag = struct.unpack("<H", data[start + 24:start + 26])[0]
            info["fmt"] = {"format_tag": tag, "channels": ch, "sample_rate": rate, "bits": bits}
        elif cid == "data":
            info["data_range"] = (start, min(end, len(data)))
        elif cid == "LIST" and data[start:start + 4] == b"INFO":
            p = start + 4
            while p + 8 <= min(end, len(data)):
                sid = data[p:p + 4].decode("latin-1")
                ssz = struct.unpack("<I", data[p + 4:p + 8])[0]
                val = data[p + 8:p + 8 + ssz].split(b"\x00")[0].decode("utf-8", "replace")
                info["info_tags"][sid] = val
                p += 8 + ssz + (ssz & 1)
        if trunc:
            truncated = True
            break
        pos = end + (size & 1)
    if not truncated and pos < len(data):  # bytes the container does not account for
        info["trailing_bytes"] = len(data) - pos
    return info


def decode_wav(data, riff):
    """Decode PCM/float WAV to float array (n, ch) + integer array (or None)."""
    f, dr = riff["fmt"], riff["data_range"]
    if not f or not dr:
        return None
    tag, ch, bits = f["format_tag"], max(f["channels"], 1), f["bits"]
    raw = data[dr[0]:dr[1]]
    ints = None
    if tag == 1:
        if bits == 8:
            ints = np.frombuffer(raw, np.uint8).astype(np.int32) - 128
            scale = 128.0
        elif bits == 16:
            ints = np.frombuffer(raw[:len(raw) // 2 * 2], "<i2").astype(np.int32)
            scale = 32768.0
        elif bits == 24:
            n = len(raw) // 3
            b = np.frombuffer(raw[:n * 3], np.uint8).reshape(-1, 3).astype(np.int32)
            ints = b[:, 0] | (b[:, 1] << 8) | (b[:, 2] << 16)
            ints = np.where(ints & 0x800000, ints - 0x1000000, ints)
            scale = 8388608.0
        elif bits == 32:
            ints = np.frombuffer(raw[:len(raw) // 4 * 4], "<i4").astype(np.int64)
            scale = 2147483648.0
        else:
            return None
        x = ints.astype(np.float64) / scale
    elif tag == 3 and bits in (32, 64):
        dtype = "<f4" if bits == 32 else "<f8"
        w = bits // 8
        x = np.frombuffer(raw[:len(raw) // w * w], dtype).astype(np.float64)
    else:
        return None
    n = len(x) // ch * ch
    x = x[:n].reshape(-1, ch)
    if ints is not None:
        ints = ints[:n]
    return {"x": x, "ints": ints, "sr": f["sample_rate"], "bits": bits, "ch": ch}


def decode_generic(path):
    """Fallback for MP3/FLAC/OGG using the optional 'soundfile' package."""
    try:
        import soundfile as sf
        x, sr = sf.read(path, always_2d=True)
        return {"x": x, "ints": None, "sr": sr, "bits": None, "ch": x.shape[1]}
    except Exception:
        return None


def read_tags_mutagen(path):
    try:
        import mutagen
        m = mutagen.File(path)
        if m is None:
            return {}
        return {str(k): str(v)[:200] for k, v in (m.tags or {}).items()}
    except Exception:
        return {}


# --------------------------------------------------------------------------- signal analysis
def analyze_signal(audio, F):
    x_all, sr = audio["x"], audio["sr"]
    x = x_all.mean(axis=1)
    n = len(x)
    stats = {}
    events = []      # (time, label) for the plot
    aux = {}
    if n < sr * 0.1:
        F.add("low", "signal", "Recording is extremely short", f"{n / sr:.3f} s of audio")
        return stats, events, aux

    peak = float(np.max(np.abs(x)))
    rms = float(np.sqrt(np.mean(x ** 2)))
    stats.update({
        "duration_s": round(n / sr, 3), "sample_rate": sr, "channels": audio["ch"],
        "bit_depth": audio["bits"], "peak_dBFS": round(float(db(peak)), 2),
        "rms_dBFS": round(float(db(rms)), 2), "dc_offset": round(float(np.mean(x)), 6),
    })
    clip = float(np.mean(np.abs(x) >= 0.999))
    stats["clipped_fraction"] = round(clip, 6)
    if clip > 0.001:
        F.add("low", "signal", "Clipping detected", f"{clip * 100:.2f}% of samples at full scale")
    if abs(stats["dc_offset"]) > 0.01:
        F.add("low", "signal", "Noticeable DC offset", f"mean = {stats['dc_offset']}")

    # ---- 1. digital silence (exact zeros) ------------------------------------------------
    min_run = max(int(0.005 * sr), 8)
    ctx = int(0.05 * sr)
    for s, e in runs(np.all(x_all == 0, axis=1)):
        if e - s < min_run:
            continue
        t0, dur = s / sr, (e - s) / sr
        if s == 0 or e >= n:
            F.add("info", "tamper", "Digital silence at file boundary", f"{dur * 1000:.0f} ms", t0)
            continue
        before = np.sqrt(np.mean(x[max(0, s - ctx):s] ** 2))
        after = np.sqrt(np.mean(x[e:e + ctx] ** 2))
        if max(before, after) > 1e-4:   # > -80 dBFS around it: real recordings are never exactly zero
            F.add("medium", "tamper", "Digital silence between live audio (possible deletion/overwrite)",
                  f"{dur * 1000:.0f} ms of exact zeros; surrounding level "
                  f"{db(max(before, after)):.0f} dBFS", t0)
            events.append((t0, "digital silence"))
        else:
            F.add("info", "tamper", "Digital silence in a quiet region", f"{dur * 1000:.0f} ms", t0)

    # ---- 2. waveform discontinuities (splice points) -------------------------------------
    d = np.abs(np.diff(x))
    w = max(int(0.01 * sr), 8)
    local = uniform_filter1d(d, size=2 * w + 1, mode="nearest")
    local_ex = (local * (2 * w + 1) - d) / (2 * w)
    ratio = d / (local_ex + 1e-9)
    idx = np.where((ratio > 12) & (d > 0.02))[0]
    last = -10 ** 9
    found = []
    for i in idx:
        if i - last > int(0.005 * sr):
            found.append(i)
        last = i
    stats["discontinuities"] = len(found)
    for i in found[:30]:
        F.add("medium", "tamper", "Abrupt waveform discontinuity (possible splice/cut point)",
              f"jump = {d[i]:.3f} FS, {ratio[i]:.0f}x local average", i / sr)
        events.append((i / sr, "discontinuity"))
    if len(found) > 30:
        F.add("info", "tamper", "More discontinuities omitted", f"{len(found) - 30} additional")

    # ---- 3. background-noise-floor consistency ------------------------------------------
    fl = int(0.025 * sr)
    nfr = n // fl
    frames = x[:nfr * fl].reshape(nfr, fl)
    fdb = db(np.sqrt(np.mean(frames ** 2, axis=1)))
    aux["frame_db"] = fdb
    aux["frame_t"] = (np.arange(nfr) + 0.5) * fl / sr
    seg = 40  # 1.0 s
    floors = []
    for i in range(0, nfr - seg + 1, seg):
        v = fdb[i:i + seg]
        v = v[v > -100]                      # ignore digital-silence frames (handled separately above)
        floors.append(float(np.percentile(v, 10)) if len(v) >= 10 else np.nan)
    fin = [v for v in floors if not np.isnan(v)]
    stats["noise_floor_dB_range"] = [round(min(fin), 1), round(max(fin), 1)] if fin else None
    for k in range(1, len(floors)):
        a, b = floors[k - 1], floors[k]
        if not (np.isnan(a) or np.isnan(b)) and abs(b - a) > 12:
            t = k * seg * fl / sr
            F.add("medium", "tamper", "Abrupt change in background noise floor (different recording source/edit?)",
                  f"{a:.0f} dBFS -> {b:.0f} dBFS", t)
            events.append((t, "noise-floor shift"))

    # ---- 4. spectral cut-off (lossy origin / resampling) --------------------------------
    nyq = sr / 2
    if nyq > 8000 and n > 4096 * 2:
        f, p = signal.welch(x, sr, nperseg=4096)
        pdb = 10 * np.log10(p + 1e-20)
        aux["psd"] = (f, pdb)
        df = f[1] - f[0]
        bw = max(int(1000 / df), 2)
        cs = np.concatenate(([0], np.cumsum(pdb)))
        lo, hi = int(4000 / df), len(pdb) - bw
        if hi > lo:
            ii = np.arange(lo, hi)
            step = (cs[ii] - cs[ii - bw]) / bw - (cs[ii + bw] - cs[ii]) / bw
            k = int(np.argmax(step))
            cutoff = float(f[ii[k]])
            stats["spectral_cutoff_hz"] = round(cutoff, 0) if step[k] > 25 else None
            if step[k] > 25 and cutoff < 0.95 * nyq:
                F.add("low", "tamper", "Sharp spectral cut-off (possible lossy/MP3 origin or resampling)",
                      f"energy drops {step[k]:.0f} dB near {cutoff:.0f} Hz (Nyquist = {nyq:.0f} Hz)")
    return stats, events, aux



# --------------------------------------------------------------------------- ENF analysis
def extract_enf(x, sr, nominal=50.0, win_s=4.0, hop_s=0.5):
    """Electric Network Frequency (mains hum) estimate over time.
    Tries the fundamental and 2nd harmonic, keeps whichever has the better SNR.
    Returns dict(t, f, snr_db, harmonic) or None if the recording is too short/low-rate."""
    fs = 1000
    if sr < 2 * (2 * nominal + 2) or len(x) < sr * win_s * 1.5:
        return None
    g = np.gcd(int(sr), fs)
    y = signal.resample_poly(x, fs // g, int(sr) // g)
    nper, hop, nfft = int(win_s * fs), int(hop_s * fs), 2 ** 16
    best = None
    for h in (1, 2):
        lo, hi = h * nominal - 1.0, h * nominal + 1.0
        sos = signal.butter(4, [lo - 0.5, hi + 0.5], btype="band", fs=fs, output="sos")
        z = signal.sosfiltfilt(sos, y)
        freqs = np.fft.rfftfreq(nfft, 1 / fs)
        band = (freqs >= lo) & (freqs <= hi)
        win = np.hanning(nper)
        T, F, S = [], [], []
        for st in range(0, len(z) - nper, hop):
            spec = np.abs(np.fft.rfft(z[st:st + nper] * win, nfft)) ** 2
            sb = spec[band]
            k = int(np.argmax(sb))
            if 0 < k < len(sb) - 1:                       # parabolic interpolation
                a, b, c = np.log(sb[k - 1] + 1e-30), np.log(sb[k] + 1e-30), np.log(sb[k + 1] + 1e-30)
                k = k + 0.5 * (a - c) / (a - 2 * b + c + 1e-30)
            F.append((freqs[band][0] + k * (freqs[1] - freqs[0])) / h)
            S.append(10 * np.log10(sb.max() / (np.median(sb) + 1e-30)))
            T.append((st + nper / 2) / fs)
        cand = {"t": np.array(T), "f": np.array(F), "snr_db": np.array(S), "harmonic": h}
        if best is None or np.median(cand["snr_db"]) > np.median(best["snr_db"]):
            best = cand
    return best


def analyze_enf(x, sr, nominal, F):
    res = extract_enf(x, sr, nominal)
    if res is None:
        F.add("info", "enf", "ENF analysis skipped", "recording too short (< 6 s) or sample rate too low")
        return {}, None
    snr = float(np.median(res["snr_db"]))
    stats = {"enf_nominal_hz": nominal, "enf_harmonic_used": res["harmonic"], "enf_median_snr_db": round(snr, 1)}
    if snr < 12:
        stats["enf_present"] = False
        F.add("info", "enf", "No usable ENF trace found",
              f"median peak-to-floor ratio {snr:.1f} dB (device may filter mains hum, or recording was battery-powered/outdoors)")
        return stats, None
    good = res["snr_db"] > 8
    f, t = res["f"], res["t"]
    stats.update({"enf_present": True, "enf_mean_hz": round(float(np.mean(f[good])), 4),
                  "enf_std_hz": round(float(np.std(f[good])), 4),
                  "enf_min_hz": round(float(np.min(f[good])), 3), "enf_max_hz": round(float(np.max(f[good])), 3)})
    if abs(stats["enf_mean_hz"] - nominal) > 0.5:
        F.add("medium", "enf", "ENF mean is far from the chosen grid frequency",
              f"mean {stats['enf_mean_hz']} Hz vs nominal {nominal} Hz - wrong grid (e.g. 50 vs 60 Hz) or synthetic hum")
    # Grid frequency drifts slowly. A cut/insert makes the mean ENF before and after the edit disagree.
    # Compare 4-frame means either side of each point, skipping 3 frames that the 4 s STFT window smears.
    w, gap, thr = 4, 3, 0.07
    cands = []
    for i in range(w + gap, len(f) - w - gap):
        A, B = slice(i - gap - w, i - gap), slice(i + gap, i + gap + w)
        if good[A].sum() >= 3 and good[B].sum() >= 3:
            step = abs(f[B][good[B]].mean() - f[A][good[A]].mean())
            if step > thr:
                cands.append((i, step))
    group = []
    for c in cands + [(10 ** 9, 0)]:
        if group and c[0] - group[-1][0] > 8:
            i, st = max(group, key=lambda g: g[1])
            F.add("medium", "enf", "ENF discontinuity (possible cut/insert)",
                  f"mean mains frequency shifts by {st:.3f} Hz across this point", t[i])
            group = []
        group.append(c)
    bad = ~good
    for s0, e0 in runs(bad):
        if t[min(e0, len(t)) - 1] - t[s0] > 3.0 and 0 < s0 and e0 < len(t):
            F.add("low", "enf", "ENF trace vanishes for a section (possible replaced/inserted audio)",
                  f"{t[e0 - 1] - t[s0]:.1f} s without mains hum", t[s0])
    return stats, res

# --------------------------------------------------------------------------- hidden data
def hidden_data(data, riff, audio, F):
    # trailing data / RIFF size mismatch
    if riff["is_riff"]:
        if riff["trailing_bytes"] > 1:
            F.add("high", "hidden", "Data appended after the last RIFF chunk",
                  f"{riff['trailing_bytes']} extra bytes not accounted for by the container")
        if riff["declared_size"] is not None:
            if riff["actual_size"] > riff["declared_size"] + 1:
                F.add("medium", "container", "File larger than RIFF header declares",
                      f"header says {riff['declared_size']} B, file is {riff['actual_size']} B")
            elif riff["actual_size"] < riff["declared_size"]:
                F.add("medium", "container", "File smaller than RIFF header declares (truncated?)",
                      f"header says {riff['declared_size']} B, file is {riff['actual_size']} B")
    # embedded file signatures
    for sig, name in EMBED_SIGS.items():
        pos = data.find(sig, 1)
        if pos != -1:
            F.add("high", "hidden", f"Embedded {name} signature inside audio file", f"at byte offset {pos}")
    # LSB steganography (simple sequential embedding)
    ints = audio.get("ints") if audio else None
    if ints is not None and len(ints) >= 1024:
        lsb = (ints & 1).astype(np.uint8)
        res = {"lsb_ones_ratio": round(float(lsb.mean()), 4)}
        nbits = min(len(lsb), 8 * 4096) // 8 * 8
        hit = False
        for order in ("big", "little"):
            bs = np.packbits(lsb[:nbits], bitorder=order).tobytes()
            head = np.frombuffer(bs[:64], np.uint8)
            printable = float(np.mean(((head >= 32) & (head < 127)) | (head == 10) | (head == 13)))
            sig = next((nm for s, nm in EMBED_SIGS.items() if bs.startswith(s)), None)
            if printable > 0.9 or sig:
                preview = bs[:60].decode("ascii", "replace") if printable > 0.9 else sig
                F.add("high", "hidden", "LSB plane contains structured data (steganography)",
                      f"{order}-bit-order read of first LSBs gives: {preview!r}")
                res["lsb_decoded_preview"] = preview
                hit = True
                break
        return res
    return {}


# --------------------------------------------------------------------------- plotting
def make_plot(audio, events, aux, path, title):
    import warnings
    warnings.filterwarnings("ignore", category=RuntimeWarning)
    x = audio["x"].mean(axis=1)
    sr = audio["sr"]
    t = np.arange(len(x)) / sr
    step = max(1, len(x) // 60000)
    enf = aux.get("enf")
    fig, ax = plt.subplots(4 if enf else 3, 1, figsize=(11, 10 if enf else 8), sharex=True)
    ax[0].plot(t[::step], x[::step], lw=0.5, color="#1f77b4")
    ax[0].set_ylabel("Amplitude")
    ax[0].set_title(title)
    colors = {"digital silence": "#d62728", "discontinuity": "#ff7f0e", "noise-floor shift": "#9467bd", "ENF discontinuity": "#17becf"}
    seen = set()
    for te, lab in events:
        for a in ax:
            a.axvline(te, color=colors.get(lab, "red"), lw=1.2, alpha=0.8,
                      label=lab if (lab not in seen and a is ax[0]) else None)
        seen.add(lab)
    if seen:
        ax[0].legend(loc="upper right", fontsize=8)
    ax[1].specgram(x, NFFT=1024, Fs=sr, noverlap=512, cmap="magma")
    ax[1].set_ylabel("Frequency (Hz)")
    if "frame_db" in aux:
        ax[2].plot(aux["frame_t"], aux["frame_db"], color="#2ca02c", lw=0.8)
    ax[2].set_ylabel("Frame level (dBFS)")
    if enf:
        ok = enf["snr_db"] > 8
        ax[3].plot(enf["t"][ok], enf["f"][ok], ".", ms=3, color="#c0392b")
        ax[3].set_ylabel("ENF (Hz)")
    ax[-1].set_xlabel("Time (s)")
    fig.tight_layout()
    fig.savefig(path, dpi=110)
    plt.close(fig)


# --------------------------------------------------------------------------- HTML report
def html_report(rep, png_path, out_path):
    e = html.escape
    sev_col = {"info": "#6c757d", "low": "#0d6efd", "medium": "#fd7e14", "high": "#dc3545"}
    rows = ""
    for f in rep["findings"]:
        tm = "" if f["time_s"] is None else f"{f['time_s']:.3f} s"
        rows += (f"<tr><td style='color:#fff;background:{sev_col[f['severity']]}'>{f['severity'].upper()}</td>"
                 f"<td>{e(f['category'])}</td><td>{e(f['title'])}</td><td>{e(f['detail'])}</td><td>{tm}</td></tr>")
    if not rows:
        rows = "<tr><td colspan=5>No indicators found.</td></tr>"

    def kv(d):
        return "".join(f"<tr><th>{e(str(k))}</th><td>{e(str(v))}</td></tr>" for k, v in d.items())

    chunks = "".join(f"<tr><td>{e(c['id'])}</td><td>{c['offset']}</td><td>{c['size']}</td></tr>"
                     for c in rep["container"].get("chunks", []))
    img = ""
    if png_path and os.path.exists(png_path):
        img = "<img style='max-width:100%' src='data:image/png;base64," + \
              base64.b64encode(open(png_path, "rb").read()).decode() + "'>"
    vcol = {"NO INDICATORS FOUND": "#198754", "LOW SUSPICION": "#0d6efd",
            "MEDIUM SUSPICION": "#fd7e14", "HIGH SUSPICION": "#dc3545"}[rep["verdict"]]
    doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>Audio Forensic Report</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:30px;max-width:1100px}}
table{{border-collapse:collapse;width:100%;margin-bottom:18px}}td,th{{border:1px solid #ccc;padding:6px 9px;text-align:left;font-size:14px}}
th{{background:#f1f3f5;width:220px}}h2{{border-bottom:2px solid #333;padding-bottom:3px}}
.v{{display:inline-block;padding:8px 18px;color:#fff;font-weight:bold;border-radius:6px;background:{vcol}}}</style></head><body>
<h1>Audio Forensic Analysis Report</h1>
<p><span class="v">{rep['verdict']}</span> &nbsp; risk score {rep['score']}</p>
<h2>1. Case &amp; chain of custody</h2><table>{kv(rep['case'])}</table>
<h2>2. Evidence integrity</h2><table>{kv(rep['integrity'])}</table>
<h2>3. File &amp; format</h2><table>{kv(rep['file'])}</table>
<h2>4. Container (RIFF) structure</h2><table><tr><th>Chunk</th><th>Offset</th><th>Size</th></tr>{chunks}</table>
<table>{kv(rep['metadata'])}</table>
<h2>5. Signal statistics</h2><table>{kv(rep['signal'])}</table>
<h2>6. Findings</h2><table><tr><th style="width:80px">Severity</th><th style="width:90px">Category</th><th>Finding</th><th>Detail</th><th style="width:80px">Time</th></tr>{rows}</table>
<h2>7. Visualisation</h2>{img}
<p style="color:#666;font-size:12px">Generated by AudioForensics v{VERSION}. Findings are indicators that require examiner
interpretation and are not conclusive proof of manipulation.</p></body></html>"""
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(doc)


# --------------------------------------------------------------------------- main workflows
def analyze(path, case, examiner, outdir, enf_nominal=None):
    path = os.path.abspath(path)
    os.makedirs(outdir, exist_ok=True)
    with open(path, "rb") as fh:            # read-only: evidence is never modified
        data = fh.read()
    h_before = hashes(data)
    st = os.stat(path)
    F = Findings()

    # format check
    detected = identify_format(data)
    ext = os.path.splitext(path)[1].lower()
    expected = EXT_FORMAT.get(ext)
    if detected == "UNKNOWN":
        F.add("medium", "format", "Unrecognised file signature", f"first bytes: {data[:8].hex()}")
    if expected and detected != "UNKNOWN" and expected != detected:
        F.add("medium", "format", "Extension does not match real file type",
              f"extension '{ext}' suggests {expected} but content is {detected}")

    riff = parse_riff(data)
    metadata = dict(riff["info_tags"])
    for c in riff["chunks"]:
        if c["id"] not in KNOWN_CHUNKS:
            F.add("low", "container", f"Unknown/non-standard chunk '{c['id']}'", f"offset {c['offset']}, {c['size']} bytes")
        if c["truncated"]:
            F.add("medium", "container", f"Chunk '{c['id']}' extends past end of file", "file truncated or header altered")
    if detected != "WAV":
        metadata.update(read_tags_mutagen(path))
    for k, v in metadata.items():
        if any(h in str(v).lower() for h in EDITOR_HINTS):
            F.add("low", "metadata", "Editing/processing software trace in metadata", f"{k} = {v}")

    # decode audio
    audio = decode_wav(data, riff) if riff["is_riff"] else None
    if audio is None:
        audio = decode_generic(path)
    if audio is None:
        F.add("info", "signal", "Audio could not be decoded",
              "Only PCM/float WAV is supported natively; install 'soundfile' for FLAC/OGG/MP3")
    stats, events, aux = ({}, [], {})
    if audio is not None:
        stats, events, aux = analyze_signal(audio, F)
        if enf_nominal:
            es, er = analyze_enf(audio["x"].mean(axis=1), audio["sr"], float(enf_nominal), F)
            stats.update(es)
            if er is not None:
                aux["enf"] = er
                events += [(fi["time_s"], "ENF discontinuity") for fi in F.items
                           if fi["category"] == "enf" and fi["time_s"] is not None and "discontinuity" in fi["title"]]
    stats.update(hidden_data(data, riff, audio, F))

    png = os.path.join(outdir, "analysis.png")
    if audio is not None and len(audio["x"]) > 0:
        make_plot(audio, events, aux, png, os.path.basename(path))
    else:
        png = None

    with open(path, "rb") as fh:
        h_after = hashes(fh.read())
    if h_before != h_after:
        F.add("high", "integrity", "Evidence hash changed during analysis!", "")

    F.items.sort(key=lambda i: (-SEV_WEIGHT[i["severity"]], i["time_s"] or 0))
    rep = {
        "case": {"case_id": case, "examiner": examiner, "analysis_time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                 "tool": f"AudioForensics v{VERSION}", "python": sys.version.split()[0]},
        "integrity": {"MD5": h_before["md5"], "SHA-1": h_before["sha1"], "SHA-256": h_before["sha256"],
                      "hash_unchanged_after_analysis": h_before == h_after},
        "file": {"path": path, "size_bytes": st.st_size, "extension": ext or "-", "detected_type": detected,
                 "modified_utc": ts(st.st_mtime), "changed_utc (inode)": ts(st.st_ctime), "accessed_utc": ts(st.st_atime)},
        "container": riff,
        "metadata": metadata or {"-": "no metadata found"},
        "signal": stats,
        "findings": F.items, "score": F.score(), "verdict": F.verdict(),
    }
    rep["container"] = {k: v for k, v in riff.items()}
    with open(os.path.join(outdir, "report.json"), "w") as fh:
        json.dump(rep, fh, indent=2, default=_js)
    html_report(rep, png, os.path.join(outdir, "report.html"))
    return rep


def compare_lines(a, b):
    """Compare two recordings; returns a list of text lines (used by CLI and GUI)."""
    out = []
    da, db_ = open(a, "rb").read(), open(b, "rb").read()
    ha, hb = hashes(da), hashes(db_)
    out += [f"SHA-256 A: {ha['sha256']}", f"SHA-256 B: {hb['sha256']}"]
    if ha == hb:
        return out + ["=> Files are bit-for-bit IDENTICAL."]
    out.append("=> Files differ at the byte level.")
    A, B = decode_wav(da, parse_riff(da)), decode_wav(db_, parse_riff(db_))
    if not A or not B:
        return out + ["(sample-level comparison needs two PCM WAV files)"]
    xa, xb = A["x"].mean(axis=1), B["x"].mean(axis=1)
    out.append(f"Duration A = {len(xa) / A['sr']:.3f}s, B = {len(xb) / B['sr']:.3f}s")
    m = min(len(xa), len(xb))
    diff = np.abs(xa[:m] - xb[:m]) > 1e-6
    if not diff.any():
        return out + ["Audio samples identical over the common length (difference is in header/metadata/length)."]
    idx = np.where(diff)[0]
    out.append(f"{diff.mean() * 100:.2f}% of samples differ; first at {idx[0] / A['sr']:.3f}s, last at {idx[-1] / A['sr']:.3f}s")
    if len(xa) != len(xb):
        out.append("Length differs -> content was inserted or removed.")
    return out


def compare(a, b):
    print("\n".join(compare_lines(a, b)))


def main():
    ap = argparse.ArgumentParser(description="Audio digital-forensics toolkit")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="full forensic analysis of one file")
    a.add_argument("file")
    a.add_argument("--case", default="CASE-001")
    a.add_argument("--examiner", default="Unknown")
    a.add_argument("--out", default="report")
    a.add_argument("--enf", type=float, default=None, help="nominal mains frequency (50 India/EU, 60 US) to enable ENF analysis")
    c = sub.add_parser("compare", help="compare two recordings")
    c.add_argument("file_a")
    c.add_argument("file_b")
    args = ap.parse_args()

    if args.cmd == "analyze":
        rep = analyze(args.file, args.case, args.examiner, args.out, args.enf)
        print(f"\n=== {os.path.basename(args.file)} : {rep['verdict']} (score {rep['score']}) ===")
        print(f"SHA-256: {rep['integrity']['SHA-256']}")
        for f in rep["findings"]:
            t = "" if f["time_s"] is None else f" @ {f['time_s']:.3f}s"
            print(f"[{f['severity'].upper():6}] {f['title']}{t}\n         {f['detail']}")
        print(f"\nReports written to: {os.path.abspath(args.out)}/ (report.html, report.json, analysis.png)")
    else:
        compare(args.file_a, args.file_b)


if __name__ == "__main__":
    main()
