import streamlit as st
import pandas as pd
from reportlab.pdfgen import canvas
import io
import re
import os
import math
from collections import Counter
from urllib.parse import urlparse

# --- Page Configuration ---
st.set_page_config(page_title="CyberSentinel Pro", page_icon="🛡️", layout="wide")

# --- Log Management ---
LOG_FILE = "forensic_logs.csv"

# --- Security Disclaimer ---
if 'agreed' not in st.session_state: st.session_state.agreed = False
if not st.session_state.agreed:
    st.title("🛡️ CyberSentinel | Disclaimer")
    st.markdown("This tool is for security research. By proceeding, you accept all liability.")
    if st.button("I Accept & Proceed"):
        st.session_state.agreed = True
        st.rerun()
    st.stop()

# --- Forensic Engine ---
def analyze_url_deep(url):
    # Basic Validation
    if not url or len(url) < 5:
        return "INVALID", 0, {"Error": "URL too short."}, ["N/A"]
    
    if not re.match(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url):
        return "INVALID", 0, {"Syntax Error": "Invalid URL format."}, ["N/A"]
    
    entropy_score = 0
    phishing_score = 0
    findings = {}
    
    # Entropy Calculation
    counts = Counter(url)
    total_len = len(url)
    probs = [c / total_len for c in counts.values()]
    entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    
    if entropy > 4.2: 
        entropy_score = 6
        findings["High Entropy"] = f"Randomness score: {entropy:.2f}."
    
    # Heuristics
    if any(k in url.lower() for k in ['login', 'verify', 'free', 'win', 'promo']): 
        phishing_score = 9
        findings["Phishing Keywords"] = "Social engineering patterns detected."

    # Scoring
    total_score = int((entropy_score * 0.4) + (phishing_score * 0.6))
    status = "CRITICAL" if total_score >= 6 else "WARNING" if total_score >= 3 else "SECURE"
    recommendation = "BLOCK domain" if "CRITICAL" in status else "Proceed with caution" if "WARNING" in status else "Safe"
    
    return status, total_score, findings, [recommendation]

# --- Forensic Report Generator ---
def generate_forensic_report(df):
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer)
    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, 820, "CYBER SENTINEL | FORENSIC ANALYSIS REPORT")
    p.setFont("Helvetica", 10)
    p.drawString(50, 800, f"Generated: {pd.Timestamp.now()}")
    p.line(50, 790, 550, 790)
    
    y = 760
    for _, row in df.iterrows():
        p.setFont("Helvetica-Bold", 11)
        p.drawString(50, y, f"Target: {row['URL']}")
        p.setFont("Helvetica", 10)
        p.drawString(50, y-15, f"Risk Score: {row['Risk']} | Status: {row['Status']}")
        y -= 40
        if y < 50: p.showPage(); y = 800
    p.save()
    buffer.seek(0)
    return buffer



# --- UI Interface ---
st.title("🌐 CyberSentinel | Ultimate Forensic OS")

col1, col2 = st.columns([2, 1])

with col1:
    url_target = st.text_input("Enter Target URL:")
    if st.button("Initiate Forensic Scan"):
        if url_target:
            status, score, findings, recs = analyze_url_deep(url_target)
            
            # Save to Logs
            new_log = pd.DataFrame([{"URL": url_target, "Status": status, "Risk": score, "Timestamp": pd.Timestamp.now()}])
            if os.path.exists(LOG_FILE):
                new_log.to_csv(LOG_FILE, mode='a', header=False, index=False)
            else:
                new_log.to_csv(LOG_FILE, index=False)
            
            # Visual Feedback
            if "CRITICAL" in status: st.error(f"### 🚨 {status}"); st.warning(f"*Action:* {recs[0]}")
            elif "WARNING" in status: st.warning(f"### ⚠️ {status}"); st.info(f"*Action:* {recs[0]}")
            else: st.success(f"### ✅ {status}"); st.success(f"*Action:* {recs[0]}")
            
            st.metric("Weighted Threat Score", f"{score}/15")
        else: st.warning("Please enter a valid URL.")

with col2:
    if st.button("🗑️ Clear System Logs"):
        if os.path.exists(LOG_FILE): os.remove(LOG_FILE)
        st.rerun()

# --- Historical Analysis ---
if os.path.exists(LOG_FILE):
    st.subheader("Deep Log Analysis")
    df = pd.read_csv(LOG_FILE)
    st.dataframe(df, use_container_width=True)
    st.download_button("📥 Export Forensic Report", generate_forensic_report(df), "Forensic_Report.pdf", "application/pdf")

st.markdown("---")
st.caption("©️ 2026 CyberSentinel Neural OS | Shahad Ali Al-Mastour")
