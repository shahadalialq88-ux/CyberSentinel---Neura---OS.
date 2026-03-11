import streamlit as st
import pandas as pd
from reportlab.pdfgen import canvas
import io
import re
import math
from collections import Counter
from urllib.parse import urlparse
import os

"""
Project: CyberSentinel Neural OS - Ultimate Edition (v4.0)
Author: Shahad Ali Al-Mastour
Description: Enterprise Forensic System with Persistent Logging & Weighted Intelligence
"""

# --- Page Config ---
st.set_page_config(page_title="CyberSentinel Pro", page_icon="🛡️", layout="wide")

# --- Log Management ---
LOG_FILE = "forensic_logs.csv"

def save_to_log(data):
    df = pd.DataFrame([data])
    if os.path.exists(LOG_FILE):
        df.to_csv(LOG_FILE, mode='a', header=False, index=False)
    else:
        df.to_csv(LOG_FILE, index=False)

# --- Forensic Engine ---
def analyze_url_deep(url):
    if not re.match(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url):
        return "INVALID", 0, {"Syntax Error": "Invalid URL format."}, ["N/A"]
    
    # Weighted scoring variables
    entropy_score = 0
    phishing_score = 0
    findings = {}
    
    probs = [c / len(url) for c in Counter(url).values()]
    entropy = -sum(p * math.log2(p) for p in probs)
    if entropy > 4.2: 
        entropy_score = 6
        findings["High Entropy"] = f"Randomness score of {entropy:.2f}."
    
    if any(k in url.lower() for k in ['login', 'verify', 'free', 'win']): 
        phishing_score = 9
        findings["Phishing Keywords"] = "High-risk patterns detected."

    total_score = int((entropy_score * 0.4) + (phishing_score * 0.6))
    status = "CRITICAL" if total_score >= 6 else "WARNING" if total_score >= 3 else "SECURE"
    recommendation = "BLOCK domain" if "CRITICAL" in status else "Proceed with caution" if "WARNING" in status else "Safe"
    
    return status, total_score, findings, [recommendation]

# --- PDF Generator ---
def generate_forensic_report(data):
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer)
    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, 820, "CYBER SENTINEL | FORENSIC ANALYSIS REPORT")
    p.setFont("Helvetica", 10)
    p.drawString(50, 800, f"Analyst: Shahad Ali Al-Mastour | {pd.Timestamp.now()}")
    p.line(50, 790, 550, 790)
    
    y = 760
    for entry in data:
        p.setFont("Helvetica-Bold", 11)
        p.drawString(50, y, f"Target: {entry['URL']}")
        p.setFont("Helvetica", 10)
        p.drawString(50, y-15, f"Risk Score: {entry['Risk']} | Status: {entry['Status']}")
        y -= 30
    p.save()
    buffer.seek(0)
    return buffer



# --- UI Interface ---
st.title("🌐 CyberSentinel | Ultimate Forensic OS")

url_target = st.text_input("Enter URL to Analyze:")

if st.button("Initiate Forensic Scan"):
    if url_target:
        # Check for duplication in local logs
        if os.path.exists(LOG_FILE):
            logs = pd.read_csv(LOG_FILE)
            if url_target in logs['URL'].values:
                st.info("⚠️ This URL was already scanned and logged.")
        
        status, score, findings, recs = analyze_url_deep(url_target)
        
        # Save to persistent log
        log_entry = {"URL": url_target, "Status": status, "Risk": score, "Timestamp": pd.Timestamp.now()}
        save_to_log(log_entry)
        
        if "CRITICAL" in status: st.error(f"### 🚨 {status}"); st.warning(f"*Action:* {recs[0]}")
        elif "WARNING" in status: st.warning(f"### ⚠️ {status}"); st.info(f"*Action:* {recs[0]}")
        else: st.success(f"### ✅ {status}"); st.success(f"*Action:* {recs[0]}")
        
        st.metric("Weighted Threat Score", f"{score}/15")
    else: st.warning("Please enter a URL.")

if st.button("Clear System Logs"):
    if os.path.exists(LOG_FILE): os.remove(LOG_FILE)
    st.rerun()

if os.path.exists(LOG_FILE):
    st.subheader("Historical System Logs")
    st.dataframe(pd.read_csv(LOG_FILE), use_container_width=True)
    st.download_button("📥 Export Forensic Report", generate_forensic_report(pd.read_csv(LOG_FILE).to_dict('records')), "Report.pdf", "application/pdf")

st.caption("©️ 2026 CyberSentinel Neural OS | Shahad Ali Al-Mastour")
