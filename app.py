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
    st.markdown("### This tool is for security research. By proceeding, you accept all liability.")
    if st.button("I Accept & Proceed"):
        st.session_state.agreed = True
        st.rerun()
    st.stop()

# --- Forensic Engine ---
def analyze_url_deep(url):
    # تحويل الرابط لحروف صغيرة تلقائياً لتجنب مشاكل الـ INVALID
    url = url.strip().lower()
    
    # ضمان وجود البروتوكول للفحص
    test_url = url
    if not test_url.startswith(('http://', 'https://')):
        test_url = 'https://' + test_url
    
    # التحقق من بنية الرابط (Regex)
    if not re.match(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-f_A-F][0-9a-f_A-F]))+', test_url):
        return "INVALID", 0, {"Syntax Error": "Invalid URL format."}, ["N/A"]
    
    score = 0
    findings = {}
    
    # استخراج الدومين للتحليل الرياضي
    clean_domain = test_url.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
    
    if clean_domain:
        # حساب Shannon Entropy (كاشف العشوائية)
        probs = [c / len(clean_domain) for c in Counter(clean_domain).values()]
        entropy = -sum(p * math.log2(p) for p in probs)
        
        # إذا كانت العشوائية عالية (مثل الروابط المشبوهة)
        if entropy > 3.3: 
            score += 8
            findings["High Entropy"] = f"Detected randomness score of {entropy:.2f} (DGA Pattern)."

    # تحليل البروتوكول
    if not test_url.startswith("https://"): 
        score += 3
        findings["Insecure Protocol"] = "Unencrypted connection detected (HTTP)."
    
    # تحليل الأرقام المشبوهة
    if re.search(r'\d{5,}', url): 
        score += 3
        findings["Numeric Obfuscation"] = "Suspicious numeric sequence detected."
        
    # تحليل كلمات التصيد
    phish_keywords = ['login', 'verify', 'free', 'win', 'update', 'secure', 'account', 'bank']
    if any(k in url for k in phish_keywords): 
        score += 5
        findings["Phishing Keywords"] = "URL contains social engineering triggers."

    # تحديد الحالة النهائية
    status = "CRITICAL" if score >= 8 else "WARNING" if score >= 4 else "SECURE"
    
    recommendations = ["IMMEDIATE BLOCK: High risk of malicious activity." if "CRITICAL" in status 
                       else "PROCEED WITH CAUTION: Non-standard patterns found." if "WARNING" in status 
                       else "SAFE: No threats detected."]
    
    return status, score, findings, recommendations

# --- Forensic Report Generator ---
def generate_forensic_report(data):
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer)
    p.setFont("Helvetica-Bold", 18)
    p.drawString(50, 820, "CYBER SENTINEL | FORENSIC ANALYSIS REPORT")
    p.setFont("Helvetica", 10)
    p.drawString(50, 800, f"Analyst: Shahad Ali Al-Mastour | Date: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M')}")
    p.line(50, 790, 550, 790)
    
    y = 760
    for entry in data:
        if y < 150: p.showPage(); y = 800
        p.setFont("Helvetica-Bold", 12)
        p.drawString(50, y, f"Target: {entry['URL']}")
        p.setFont("Helvetica", 11)
        p.drawString(50, y-15, f"Risk Score: {entry['Risk']}/15 | Status: {entry['Status']}")
        y -= 35
        for title, desc in entry['Details'].items():
            p.setFont("Helvetica-Oblique", 10)
            p.drawString(70, y, f"> {title}: {desc}")
            y -= 15
        y -= 20
    p.save()
    buffer.seek(0)
    return buffer

# --- UI Interface ---
if 'history' not in st.session_state: st.session_state.history = []

st.title("🛡️ CyberSentinel | Neural Forensic OS")
st.markdown("---")

col1, col2 = st.columns([2, 1])

with col1:
    url_input = st.text_input("Enter URL for Deep Forensic Scan:", placeholder="e.g., vbw928nzn9281bz.xyz")
    if st.button("Initiate Neural Scan 🚀"):
        if url_input:
            with st.spinner('Analyzing Neural Patterns...'):
                status, score, findings, recs = analyze_url_deep(url_input)
                # تخزين النتيجة في السجل
                st.session_state.history.append({"URL": url_input, "Status": status, "Risk": score, "Details": findings})
                
                # عرض النتيجة بالألوان
                if "CRITICAL" in status: st.error(f"### 🚨 {status} THREAT")
                elif "WARNING" in status: st.warning(f"### ⚠️ {status} ALERT")
                else: st.success(f"### ✅ SYSTEM {status}")
                
                st.write(f"*Forensic Action:* {recs[0]}")
                st.metric("Risk Index", f"{score} / 15")
        else: st.warning("Please input a target URL.")

with col2:
    st.info("Neural Engine: Operational")
    st.write("This system uses Shannon Entropy to detect DGA (Domain Generation Algorithms) used by malware.")
    if st.button("🗑️ Purge Logs"):
        st.session_state.history = []
        st.rerun()

if st.session_state.history:
    st.subheader("📊 Forensic Activity Log")
    df = pd.DataFrame(st.session_state.history).drop(columns=['Details'])
    st.dataframe(df, use_container_width=True)
    st.download_button("📥 Export PDF Forensic Report", generate_forensic_report(st.session_state.history), "Forensic_Report_Shahad.pdf", "application/pdf")

st.markdown("---")
st.caption("©️ 2026 CyberSentinel Neural OS | Engineering Project by Shahad Ali Al-Mastour")
