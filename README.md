# AudioForensics – Digital Forensics Tool for Audio Evidence
Mini project · Cyber Security & Digital Forensics · Python 3

## Install & run
```bash
pip install -r requirements.txt
python make_samples.py                       # creates demo evidence in ./samples
python audio_forensics.py analyze samples/tampered.wav --case CASE-01 --examiner "Your Name" --out reports/tampered
python audio_forensics.py compare samples/original.wav samples/tampered.wav
```
Open `reports/<name>/report.html` for the report (also `report.json`, `analysis.png`).

## What it does
| Module | Technique | Forensic meaning |
|---|---|---|
| Integrity | MD5/SHA-1/SHA-256 before & after analysis, file is opened read-only | Chain of custody, proves evidence was not altered |
| Format check | Magic bytes vs. file extension | Disguised / renamed files |
| Container analysis | RIFF chunk walk, header size vs. real size, LIST/INFO tags, editor names (Audacity, FFmpeg…) | Re-saved/edited files, truncation |
| Digital silence | Runs of exact-zero samples surrounded by live noise | Deleted or overwritten speech |
| Splice detection | Sample-to-sample jump vs. local average | Cut/paste edit points |
| Noise-floor analysis | 10th-percentile frame level per 0.5 s, jumps > 12 dB | Audio from a different source/room, missing pauses |
| Spectral cut-off | Welch PSD, >25 dB step in high band | Lossy (MP3) origin, resampling |
| Hidden data | Trailing bytes after RIFF end, embedded file signatures (ZIP, PDF, PNG, EXE…), LSB-plane decoding | Steganography / data smuggling |
| Compare | Sample-by-sample diff of two WAVs | Locates where a copy differs from the original |

## Demo files
- `original.wav` → no indicators
- `tampered.wav` → 0.7 s deleted (splice), 0.3 s zero-gap, noise-floor change
- `stego.wav` → text hidden in LSBs + ZIP appended after audio
- `disguised.mp3` → WAV file renamed to .mp3

## Limitations (mention in your viva/report)
- Results are *indicators*, not proof; real speech can trigger false positives.
- Native decoding: PCM/float WAV. Other formats need `soundfile`.
- LSB check detects simple sequential embedding, not sophisticated/encrypted stego.
- Possible extensions: ENF (mains-hum) analysis for timestamp verification, MP3 double-compression
  detection, speaker verification, GUI (Tkinter/Streamlit), batch case management.

## Web GUI (upload your own audio)
```bash
pip install -r requirements.txt
streamlit run app.py
```
Open http://localhost:8501 → enter case ID/examiner → choose the mains frequency (50 Hz India) in the sidebar →
**upload** a .wav/.mp3/.flac/.ogg file → *Run forensic analysis*. You get the verdict, hashes, findings table, plots
(waveform, spectrogram, noise floor, ENF) and downloadable HTML/JSON reports. The *Compare* tab takes two WAV uploads.

## ENF (Electric Network Frequency) analysis
`python audio_forensics.py analyze samples/enf_edited.wav --enf 50 --out reports/enf`
Extracts the mains-hum frequency (50 Hz fundamental or 100 Hz harmonic) every 0.5 s with a 4 s STFT + parabolic
interpolation. Flags (a) a shift of the mean ENF across a point = cut/insert, (b) sections where the hum vanishes =
replaced audio, (c) mean ENF far from nominal = wrong grid or synthetic hum. Needs ≥ 6 s of audio recorded on a
mains-powered device; battery recorders often contain no hum.
