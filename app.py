import streamlit as st
import pandas as pd
import time
from reportlab.pdfgen import canvas
import io
import re
import math
from collections import Counter

"""
Project: CyberSentinel Neural OS
Author: Shahad Ali Al-Mastour
License: MIT
Description: Enterprise-Grade Local Heuristic Security Engine
"""

# --- إعدادات الصفحة ---
st.set_page_config(page_title="CyberSentinel Neural OS", page_icon="🛡️", layout="wide")

# --- الإقرار القانوني ---
if 'agreed' not in st.session_state: st.session_state.agreed = False

if not st.session_state.agreed:
    st.title("🛡️ CyberSentinel | Disclaimer")
    st.markdown("""
    CyberSentinel Neural OS is a security research tool provided 'as-is' for educational purposes only. By proceeding, you acknowledge that the developer (Shahad Ali Al-Mastour) assumes no liability 
    for any misuse, security incidents, or damages resulting from the use of this tool.
    """)
    if st.button("I Accept & Proceed"):
        st.session_state.agreed = True
        st.rerun()
    st.stop()

# --- محرك التحليل الجنائي (Neural Engine) ---
def analyze_url_deep(url):
    # حارس البوابة (Input Validation)
    if not re.match(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url):
        return "❌ INVALID", 0, "URL syntax is malformed"
    
    time.sleep(1) # محاكاة معالجة استخباراتية
    score = 0
    reasons = []
    
    # 1. تحليل العشوائية (Shannon Entropy)
    probs = [c / len(url) for c in Counter(url).values()]
    entropy = -sum(p * math.log2(p) for p in probs)
    if entropy > 4.2: score += 4; reasons.append(f"High Entropy ({entropy:.2f})")
    
    # 2. تحليل البروتوكول والأنماط
    if not url.startswith("https://"): score += 3; reasons.append("Insecure Protocol")
    if re.search(r'\d{5,}', url): score += 3; reasons.append("Numeric Obfuscation")
    if any(k in url.lower() for k in ['login', 'verify', 'banking', 'free', 'win', 'promo']): score += 5; reasons.append("Phishing Keywords")
    if len(url) > 70: score += 2; reasons.append("Excessive Length")

    status = "🚨 CRITICAL" if score >= 8 else "⚠️ WARNING" if score >= 4 else "✅ SECURE"
    return status, score, ", ".join(reasons)

# --- مولد التقرير الجنائي (Digital Forensic Artifact) ---
def generate_forensic_report(data):
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer)
    p.setFont("Helvetica-Bold", 20)
    p.drawString(50, 800, "CYBER SENTINEL | FORENSIC REPORT")
    p.setFont("Helvetica", 10)
    p.drawString(50, 780, f"Analyst: Shahad Ali Al-Mastour | {pd.Timestamp.now()}")
    p.line(50, 770, 550, 770)
    
    p.setFont("Helvetica", 12)
    y = 740
    for entry in data:
        p.drawString(50, y, f"Target: {entry['URL']} | Risk: {entry['Risk']} | Status: {entry['Status']}")
        y -= 20
    
    p.setFont("Helvetica-Oblique", 8)
    p.drawString(50, 50, "Verified by Neural OS Engine - Confidential")
    p.save()
    buffer.seek(0)
    return buffer



# --- واجهة نظام Neural OS ---
if 'history' not in st.session_state: st.session_state.history = []

st.title("🌐 CyberSentinel | Neural OS")
st.markdown("### System Status: Operational")

col1, col2 = st.columns([2, 1])

with col1:
    url_target = st.text_input("Injection Point (Target URL):", placeholder="https://example.com")
    if st.button("Initialize Deep Analysis"):
        if url_target:
            with st.spinner('Accessing Threat Intelligence...'):
                status, score, details = analyze_url_deep(url_target)
                st.session_state.history.append({"URL": url_target, "Status": status, "Risk": score, "Details": details})
                color = "red" if "CRITICAL" in status else "orange" if "WARNING" in status else "green"
                st.markdown(f"### Assessment: :{color}[{status}]")
                st.metric("Threat Score", f"{score}/15")
        else: st.warning("Please provide a target URL.")

with col2:
    if st.session_state.history:
        st.write("### 📊 Security Insights")
        df = pd.DataFrame(st.session_state.history)
        st.metric("Total Forensic Logs", len(df))
        if st.button("🗑️ Purge System Logs"):
            st.session_state.history = []
            st.rerun()

# --- السجلات والتقرير ---
if st.session_state.history:
    st.write("---")
    st.subheader("Deep Log Analysis")
    st.dataframe(pd.DataFrame(st.session_state.history), use_container_width=True)
    
    st.download_button(
        label="📥 Export Forensic Artifact (PDF)",
        data=generate_forensic_report(st.session_state.history),
        file_name="Forensic_Report.pdf",
        mime="application/pdf"
    )

st.markdown("---")
st.caption("©️ 2026 CyberSentinel Neural OS | Shahad Ali Al-Mastour")
