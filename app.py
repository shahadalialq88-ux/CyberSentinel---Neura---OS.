import streamlit as st
import pandas as pd
import time
from reportlab.pdfgen import canvas
import io
import re
import math
from collections import Counter

"""
Project: CyberSentinel Neural OS (Enterprise Bilingual Edition)
Author: Shahad Ali Al-Mastour
Description: Advanced Local Forensic Security Engine
"""

# --- إعدادات الصفحة ---
st.set_page_config(page_title="CyberSentinel Neural OS", page_icon="🛡️", layout="wide")

# --- الإقرار القانوني ---
if 'agreed' not in st.session_state: st.session_state.agreed = False

if not st.session_state.agreed:
    st.title("🛡️ CyberSentinel | Disclaimer / إقرار")
    st.markdown("""
    CyberSentinel Neural OS is a security research tool provided 'as-is'. By proceeding, you acknowledge that the developer (Shahad Ali Al-Mastour) assumes no liability for any misuse.
    استخدام هذه الأداة يعني موافقتك الكاملة على الشروط القانونية.
    """)
    if st.button("I Accept & Proceed / أوافق"):
        st.session_state.agreed = True
        st.rerun()
    st.stop()

# --- محرك التحليل الجنائي ---
def analyze_url_deep(url):
    # حارس البوابة (Input Validation)
    if not re.match(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url):
        return "❌ INVALID / غير صالح", 0, "URL syntax error / خطأ في صيغة الرابط"
    
    time.sleep(1) 
    score = 0
    reasons = []
    
    # التحليل الرياضي للإنتروبي
    probs = [c / len(url) for c in Counter(url).values()]
    entropy = -sum(p * math.log2(p) for p in probs)
    if entropy > 4.2: score += 4; reasons.append(f"High Entropy ({entropy:.2f})")
    
    if not url.startswith("https://"): score += 3; reasons.append("Insecure Protocol / بروتوكول غير آمن")
    if re.search(r'\d{5,}', url): score += 3; reasons.append("Numeric Obfuscation / تمويه رقمي")
    if any(k in url.lower() for k in ['login', 'verify', 'free', 'win', 'promo']): score += 5; reasons.append("Phishing Pattern / نمط تصيد")
    if len(url) > 70: score += 2; reasons.append("Excessive Length / طول زائد")
    
    status = "🚨 CRITICAL / حرج" if score >= 8 else "⚠️ WARNING / تحذير" if score >= 4 else "✅ SECURE / آمن"
    return status, score, " | ".join(reasons)

# --- وحدة التقرير الجنائي ثنائي اللغة ---
def generate_forensic_report(data):
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer)
    p.setFont("Helvetica-Bold", 18)
    p.drawString(50, 800, "CYBER SENTINEL | FORENSIC REPORT")
    p.setFont("Helvetica", 12)
    p.drawString(50, 780, f"Analyst: Shahad Ali Al-Mastour | {pd.Timestamp.now()}")
    p.line(50, 770, 550, 770)
    
    y = 740
    for entry in data:
        p.setFont("Helvetica-Bold", 12)
        p.drawString(50, y, f"Target URL: {entry['URL']}")
        p.setFont("Helvetica", 12)
        p.drawString(50, y-15, f"Risk Score: {entry['Risk']} | Status: {entry['Status']}")
        p.drawString(50, y-30, f"Forensic Evidence (Details): {entry['Details']}")
        y -= 60
    
    p.save()
    buffer.seek(0)
    return buffer

# --- واجهة النظام ---
if 'history' not in st.session_state: st.session_state.history = []

st.title("🌐 CyberSentinel | Neural OS")
st.markdown("### System Status: Operational / حالة النظام: يعمل")

col1, col2 = st.columns([2, 1])

with col1:
    url_target = st.text_input("Injection Point (Target URL) / أدخل الرابط:")
    if st.button("Initialize Deep Analysis / بدء الفحص العميق"):
        if url_target:
            with st.spinner('Accessing Threat Intelligence...'):
                status, score, details = analyze_url_deep(url_target)
                st.session_state.history.append({"URL": url_target, "Status": status, "Risk": score, "Details": details})
                st.success("Analysis Complete / اكتمل التحليل")
        else: st.warning("Please provide a target URL / يرجى إدخال الرابط.")

with col2:
    if st.session_state.history:
        st.write("### 📊 Security Insights")
        if st.button("🗑️ Secure Wipe / مسح السجلات"):
            st.session_state.history = []
            st.rerun()

# --- السجلات والتقرير ---
if st.session_state.history:
    st.write("---")
    st.subheader("Deep Log Analysis / السجلات الجنائية")
    st.dataframe(pd.DataFrame(st.session_state.history), use_container_width=True)
    
    st.download_button(
        label="📥 Export Forensic Artifact (PDF) / تصدير التقرير",
        data=generate_forensic_report(st.session_state.history),
        file_name="Forensic_Report.pdf",
        mime="application/pdf"
    )

st.markdown("---")
st.caption("©️ 2026 CyberSentinel Neural OS | Shahad Ali Al-Mastour")
