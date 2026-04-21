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
    # 1. تنظيف المدخلات وضمان وجود البروتوكول
    url = url.strip()
    original_input = url
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # 2. التحقق من بنية الرابط
    if not re.match(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url):
        return "INVALID", 0, {"Syntax Error": "Invalid URL format."}, ["N/A"]
    
    score = 0
    findings = {}
    
    # 3. تحليل الاعتلاج (Entropy) - كشف العشوائية بطريقة مضمونة
    # نستخرج النص المكتوب قبل أول "/" أو ":" بعد البروتوكول
    clean_domain = url.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
    
    if clean_domain:
        probs = [c / len(clean_domain) for c in Counter(clean_domain).values()]
        entropy = -sum(p * math.log2(p) for p in probs)
        
        # إذا كان الاعتلاج أعلى من 3.3 (حساسية عالية جداً للكشف)
        if entropy > 3.3: 
            score += 8  # نقاط كافية لتحويل الحالة لـ CRITICAL فوراً
            findings["High Entropy"] = f"Detected randomness score of {entropy:.2f} (DGA Pattern)."

    # 4. تحليل البروتوكول
    if not url.startswith("https://"): 
        score += 3
        findings["Insecure Protocol"] = "Unencrypted connection (HTTP)."
    
    # 5. تحليل الأرقام المشبوهة
    if re.search(r'\d{5,}', url): 
        score += 3
        findings["Numeric Obfuscation"] = "Suspicious numeric sequence detected."
        
    # 6. تحليل الكلمات المفتاحية للتصيد
    phish_keywords = ['login', 'verify', 'free', 'win', 'update', 'secure', 'account', 'banking']
    if any(k in url.lower() for k in phish_keywords): 
        score += 5
        findings["Phishing Keywords"] = "URL contains social engineering triggers."

    # تحديد الحالة النهائية
    status = "CRITICAL" if score >= 8 else "WARNING" if score >= 4 else "SECURE"
    
    # توصيات تقنية
    recommendations = ["IMMEDIATE BLOCK: High probability of malicious intent." if "CRITICAL" in status 
                       else "PROCEED WITH CAUTION: Non-standard patterns found." if "WARNING" in status 
                       else "SAFE: No immediate threats detected."]
    
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
        if y < 150: 
            p.showPage()
            y = 800
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
    url_target = st.text_input("Enter URL for Deep Forensic Scan:", placeholder="e.g., vbw928nzn9281bz.xyz")
    if st.button("Initiate Neural Scan 🚀"):
        if url_target:
            with st.spinner('Calculating Entropy & Heuristics...'):
                status, score, findings, recs = analyze_url_deep(url_target)
                
                # تخزين النتيجة في السجل
                full_url = url_target if url_target.startswith(('http', 'https')) else 'https://' + url_target
                st.session_state.history.append({"URL": full_url, "Status": status, "Risk": score, "Details": findings})
                
                # عرض النتيجة فوراً
                if "CRITICAL" in status: 
                    st.error(f"### 🚨 {status} THREAT DETECTED")
                elif "WARNING" in status: 
                    st.warning(f"### ⚠️ {status} ALERT")
                else: 
                    st.success(f"### ✅ SYSTEM {status}")
                
                st.write(f"*Forensic Action:* {recs[0]}")
                st.metric("Risk Index", f"{score} / 15")
        else: 
            st.warning("Please enter a target URL.")

with col2:
    st.info("Neural Engine: Operational")
    if st.button("🗑️ Clear Logs"):
        st.session_state.history = []
        st.rerun()

if st.session_state.history:
    st.subheader("📊 Historical Analysis Log")
    df_history = pd.DataFrame(st.session_state.history).drop(columns=['Details'])
    st.dataframe(df_history, use_container_width=True)
    st.download_button("📥 Download PDF Report", generate_forensic_report(st.session_state.history), f"Report_{pd.Timestamp.now().strftime('%H%M')}.pdf", "application/pdf")

st.markdown("---")
st.caption("©️ 2026 CyberSentinel Neural OS | Engineering Project by Shahad Ali Al-Mastour")
