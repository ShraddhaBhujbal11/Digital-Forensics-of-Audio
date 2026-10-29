"""AudioForensics - Streamlit web GUI.   Run:  streamlit run app.py"""
import json
import os
import tempfile

import pandas as pd
import streamlit as st

import audio_forensics as af

st.set_page_config(page_title="AudioForensics", page_icon="🎧", layout="wide")
st.title("🎧 AudioForensics - Digital Forensics of Audio Evidence")
st.caption("Upload a recording to check integrity, tampering, hidden data and mains-hum (ENF) consistency.")

SEV_ICON = {"high": "🔴", "medium": "🟠", "low": "🔵", "info": "⚪"}
VERDICT_FN = {"NO INDICATORS FOUND": st.success, "LOW SUSPICION": st.info,
              "MEDIUM SUSPICION": st.warning, "HIGH SUSPICION": st.error}

with st.sidebar:
    st.header("Case details")
    case = st.text_input("Case ID", "CASE-001")
    examiner = st.text_input("Examiner", "")
    st.header("ENF analysis")
    grid = st.selectbox("Mains frequency of recording location", ["Off", "50 Hz (India / Europe)", "60 Hz (USA)"])
    enf_nom = {"Off": None, "50 Hz (India / Europe)": 50.0, "60 Hz (USA)": 60.0}[grid]
    st.info("Evidence is opened read-only; SHA-256 is verified before and after analysis.")

tab1, tab2, tab3 = st.tabs(["🔍 Analyze", "⚖️ Compare two files", "ℹ️ About"])



def show_df(df):
    """Full-width table that works on both old and new Streamlit versions."""
    try:
        st.dataframe(df, width="stretch", hide_index=True)
    except Exception:
        st.dataframe(df, use_container_width=True, hide_index=True)


def show_img(img):
    try:
        st.image(img, width="stretch")
    except Exception:
        st.image(img, use_container_width=True)


def save_upload(up, folder):
    path = os.path.join(folder, os.path.basename(up.name))
    with open(path, "wb") as fh:
        fh.write(up.getbuffer())
    return path


with tab1:
    up = st.file_uploader("Upload audio evidence", type=["wav", "mp3", "flac", "ogg", "m4a", "aiff"])
    if up is not None:
        st.audio(up)
        if st.button("Run forensic analysis", type="primary"):
            with tempfile.TemporaryDirectory() as tmp:
                path = save_upload(up, tmp)
                with st.spinner("Analysing..."):
                    rep = af.analyze(path, case, examiner or "Unknown", os.path.join(tmp, "out"), enf_nom)
                    html_bytes = open(os.path.join(tmp, "out", "report.html"), "rb").read()
                    png = os.path.join(tmp, "out", "analysis.png")
                    png_bytes = open(png, "rb").read() if os.path.exists(png) else None
            VERDICT_FN[rep["verdict"]](f"**{rep['verdict']}** - risk score {rep['score']}")
            sig = rep["signal"]
            c = st.columns(4)
            c[0].metric("Duration", f"{sig.get('duration_s', '-')} s")
            c[1].metric("Sample rate", f"{sig.get('sample_rate', '-')} Hz")
            c[2].metric("Detected type", rep["file"]["detected_type"])
            c[3].metric("Findings", len([f for f in rep["findings"] if f["severity"] != "info"]))

            st.subheader("Evidence integrity")
            st.code(f"MD5    {rep['integrity']['MD5']}\nSHA-1  {rep['integrity']['SHA-1']}\n"
                    f"SHA-256 {rep['integrity']['SHA-256']}\nUnchanged after analysis: "
                    f"{rep['integrity']['hash_unchanged_after_analysis']}")

            st.subheader("Findings")
            if rep["findings"]:
                df = pd.DataFrame([{"": SEV_ICON[f["severity"]], "Severity": f["severity"], "Category": f["category"],
                                    "Finding": f["title"], "Detail": f["detail"],
                                    "Time (s)": f["time_s"]} for f in rep["findings"]])
                show_df(df)
            else:
                st.write("No indicators found.")

            if png_bytes:
                st.subheader("Waveform, spectrogram, noise floor" + (" and ENF" if enf_nom else ""))
                show_img(png_bytes)
            with st.expander("Signal statistics & metadata"):
                st.json({"signal": sig, "metadata": rep["metadata"], "file": rep["file"]})
            d1, d2 = st.columns(2)
            d1.download_button("⬇ HTML report", html_bytes, "forensic_report.html", "text/html")
            d2.download_button("⬇ JSON report", json.dumps(rep, indent=2, default=af._js), "forensic_report.json")

with tab2:
    st.write("Upload a reference (original) and a suspect recording to see where they differ.")
    c1, c2 = st.columns(2)
    ua = c1.file_uploader("Original / reference", type=["wav"], key="a")
    ub = c2.file_uploader("Suspect copy", type=["wav"], key="b")
    if ua and ub and st.button("Compare"):
        with tempfile.TemporaryDirectory() as tmp:
            pa, pb = save_upload(ua, tmp), os.path.join(tmp, "suspect_" + os.path.basename(ub.name))
            open(pb, "wb").write(ub.getbuffer())
            for line in af.compare_lines(pa, pb):
                st.write(line)

with tab3:
    st.markdown("""
**Modules:** hashing & chain of custody · format/extension check · RIFF container analysis · digital-silence gaps ·
splice-point detection · noise-floor consistency · spectral cut-off · appended/embedded data · LSB steganography ·
**ENF (Electric Network Frequency)** analysis · two-file comparison.

**ENF:** mains-powered recorders pick up a 50/60 Hz hum whose exact frequency wobbles in a pattern shared across the
whole grid. Cuts and inserts break that pattern, and missing hum reveals replaced audio.

Results are *indicators for an examiner*, not proof. MP3/FLAC/OGG support needs the `soundfile` package.""")
