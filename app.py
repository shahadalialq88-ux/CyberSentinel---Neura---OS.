import streamlit as st
import pandas as pd
from reportlab.pdfgen import canvas
import io
import re
import math
from collections import Counter
from urllib.parse import urlparse

"""
Project: CyberSentinel Neural OS - Professional Edition
Author: Shahad Ali Al-Mastour
Description: Enterprise-Grade Local Forensic Security Engine
"""

# --- Page Configuration ---
st.set_page_config(page_title="CyberSentinel Pro", page_icon="🛡️", layout="wide")

# --- Security Disclaimer ---
if 'agreed' not in st.session_state: st.session_state.agreed = False
if not st.session_state.agreed:
    st.title("🛡️ CyberSentinel | Disclaimer")
    st.markdown("This tool is for security research purposes. By proceeding, you acknowledge full liability.")
    if st.button("I Accept & Proceed"):
        st.session_state.agreed = True
        st.rerun()
    st.stop()

# --- Forensic Engine ---
def analyze_url_deep(url):
    # Input Validation
    if not re.match(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url):
        return "INVALID", 0, {"Syntax Error": "The URL format is invalid."}
    
    score = 0
    findings = {}
    
    # Entropy Analysis
    probs = [c / len(url) for c in Counter(url).values()]
    entropy = -sum(p * math.log2(p) for p in probs)
    if entropy > 4.2: 
        score += 4
        findings["High Entropy"] = f"Detected randomness score of {entropy:.2f}. High complexity often masks malicious intent."
    
    # Heuristic Analysis
    if not url.startswith("https://"): 
        score += 3
        findings["Insecure Protocol"] = "The connection is not encrypted (HTTP), exposing data to man-in-the-middle attacks."
    
    if re.search(r'\d{5,}', url): 
        score += 3
        findings["Numeric Obfuscation"] = "Suspicious long numeric sequence detected, often used to bypass filters."
        
    if any(k in url.lower() for k in ['login', 'verify', 'free', 'win']): 
        score += 5
        findings["Phishing Keywords"] = "Contains high-risk keywords associated with social engineering and phishing."

    status = "CRITICAL" if score >= 8 else "WARNING" if score >= 4 else "SECURE"
    return status, score, findings

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
        domain = urlparse(entry['URL']).netloc
        p.setFont("Helvetica-Bold", 12)
        p.drawString(50, y, f"Target Domain: {domain}")
        p.setFont("Helvetica", 11)
        p.drawString(50, y-15, f"Risk Score: {entry['Risk']} | Status: {entry['Status']}")
        
        y -= 35
        p.setFont("Helvetica-BoldOblique", 10)
        p.drawString(50, y, "Forensic Evidence Breakdown:")
        p.setFont("Helvetica", 10)
        
        for title, desc in entry['Details'].items():
            y -= 15
            p.drawString(70, y, f"- {title}: {desc}")
        y -= 30
    
    p.save()
    buffer.seek(0)
    return buffer

# --- UI Interface ---
if 'history' not in st.session_state: st.session_state.history = []

st.title("🌐 CyberSentinel | Professional Forensic OS")

col1, col2 = st.columns([2, 1])

with col1:
    url_target = st.text_input("Enter Target URL to Analyze:")
    if st.button("Initiate Forensic Scan"):
        if url_target:
            with st.spinner('Analyzing...'):
                status, score, findings = analyze_url_deep(url_target)
                st.session_state.history.append({"URL": url_target, "Status": status, "Risk": score, "Details": findings})
                
                # Visual Intelligence (Color Coding)
                if "CRITICAL" in status:
                    st.error(f"### 🚨 {status}")
                elif "WARNING" in status:
                    st.warning(f"### ⚠️ {status}")
                else:
                    st.success(f"### ✅ {status}")
                
                st.metric("Threat Risk Score", f"{score}/15")
        else: st.warning("Please enter a valid URL.")

with col2:
    if st.button("Secure Wipe History"):
        st.session_state.history = []
        st.rerun()

if st.session_state.history:
    st.subheader("Deep Log Analysis")
    display_df = pd.DataFrame(st.session_state.history).drop(columns=['Details'])
    st.dataframe(display_df, use_container_width=True)
    st.download_button("📥 Export Comprehensive Forensic Report", generate_forensic_report(st.session_state.history), "Detailed_Forensic_Report.pdf", "application/pdf")

st.markdown("---")
st.caption("©️ 2026 CyberSentinel Neural OS | Shahad Ali Al-Mastour")
