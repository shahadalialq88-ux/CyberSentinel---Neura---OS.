import streamlit as st
import pandas as pd
from reportlab.pdfgen import canvas
import io
import re
import math
from collections import Counter
from urllib.parse import urlparse

"""
Project: CyberSentinel Neural OS - Ultimate Edition (v3.0)
Author: Shahad Ali Al-Mastour
Description: Enterprise-Grade Forensic System with Actionable Intelligence
"""

# --- Page Config ---
st.set_page_config(page_title="CyberSentinel Pro", page_icon="🛡️", layout="wide")

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
    if not re.match(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url):
        return "INVALID", 0, {"Syntax Error": "Invalid URL format."}, ["N/A"]
    
    score = 0
    findings = {}
    
    # Entropy & Heuristics
    probs = [c / len(url) for c in Counter(url).values()]
    entropy = -sum(p * math.log2(p) for p in probs)
    if entropy > 4.2: 
        score += 4
        findings["High Entropy"] = f"Detected randomness score of {entropy:.2f}."
    
    if not url.startswith("https://"): 
        score += 3
        findings["Insecure Protocol"] = "Data is exposed to interception."
    
    if re.search(r'\d{5,}', url): 
        score += 3
        findings["Numeric Obfuscation"] = "Suspicious numeric sequence."
        
    if any(k in url.lower() for k in ['login', 'verify', 'free', 'win']): 
        score += 5
        findings["Phishing Keywords"] = "Associated with phishing/social engineering."

    status = "CRITICAL" if score >= 8 else "WARNING" if score >= 4 else "SECURE"
    
    # Actionable Intelligence
    recommendations = ["BLOCK domain" if "CRITICAL" in status else "Proceed with caution" if "WARNING" in status else "Safe to browse"]
    
    return status, score, findings, recommendations

# --- Forensic Report Generator ---
def generate_forensic_report(data):
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer)
    p.setFont("Helvetica-Bold", 18)
    p.drawString(50, 820, "CYBER SENTINEL | FORENSIC ANALYSIS REPORT")
    p.setFont("Helvetica", 10)
    p.drawString(50, 800, f"Analyst: Shahad Ali Al-Mastour | {pd.Timestamp.now()}")
    p.line(50, 790, 550, 790)
    
    y = 760
    for entry in data:
        p.setFont("Helvetica-Bold", 12)
        p.drawString(50, y, f"Target: {urlparse(entry['URL']).netloc}")
        p.setFont("Helvetica", 11)
        p.drawString(50, y-15, f"Risk Score: {entry['Risk']} | Status: {entry['Status']}")
        y -= 30
        for title, desc in entry['Details'].items():
            p.drawString(70, y, f"- {title}: {desc}")
            y -= 15
        y -= 10
    p.save()
    buffer.seek(0)
    return buffer

# --- UI Interface ---
if 'history' not in st.session_state: st.session_state.history = []

st.title("🌐 CyberSentinel | Ultimate Forensic OS")

col1, col2 = st.columns([2, 1])

with col1:
    url_target = st.text_input("Enter URL to Analyze:")
    if st.button("Initiate Forensic Scan"):
        if url_target:
            with st.spinner('Analyzing...'):
                status, score, findings, recs = analyze_url_deep(url_target)
                st.session_state.history.append({"URL": url_target, "Status": status, "Risk": score, "Details": findings})
                
                if "CRITICAL" in status: st.error(f"### 🚨 {status}"); st.warning(f"*Action:* {recs[0]}")
                elif "WARNING" in status: st.warning(f"### ⚠️ {status}"); st.info(f"*Action:* {recs[0]}")
                else: st.success(f"### ✅ {status}"); st.success(f"*Action:* {recs[0]}")
                
                st.metric("Threat Risk Score", f"{score}/15")
        else: st.warning("Please enter a valid URL.")

with col2:
    if st.button("Secure Wipe History"):
        st.session_state.history = []
        st.rerun()

if st.session_state.history:
    st.subheader("Deep Log Analysis")
    st.dataframe(pd.DataFrame(st.session_state.history).drop(columns=['Details']), use_container_width=True)
    st.download_button("📥 Export Forensic Report", generate_forensic_report(st.session_state.history), "Detailed_Forensic_Report.pdf", "application/pdf")

st.markdown("---")
st.caption("©️ 2026 CyberSentinel Neural OS | Shahad Ali Al-Mastour")
