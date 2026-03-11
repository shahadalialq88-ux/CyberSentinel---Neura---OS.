import streamlit as st
import pandas as pd
from reportlab.pdfgen import canvas
import io
import re

"""
Project: CyberSentinel
Author: Shahad Ali Al-Mastour
License: MIT
Description: Enterprise-Grade Local Heuristic Security Engine
"""

# إعداد الصفحة
st.set_page_config(page_title="CyberSentinel Pro", page_icon="🛡️", layout="wide")

# الإقرار الرسمي (Disclaimer) - مختصر ورسمي
if 'agreed' not in st.session_state:
    st.session_state.agreed = False

if not st.session_state.agreed:
    st.title("🛡️ CyberSentinel | Disclaimer")
    st.markdown("""
    CyberSentinel is a security research tool provided 'as-is' for educational purposes only. By proceeding, you acknowledge that the developer (Shahad Ali Al-Mastour) assumes no liability for any misuse, 
    security incidents, or damages resulting from the use of this tool. 
    Usage of this software constitutes full acceptance of these terms.
    """)
    if st.button("I Accept & Proceed"):
        st.session_state.agreed = True
        st.rerun()
    st.stop()

# --- محتوى الأداة الرئيسي ---
if 'history' not in st.session_state: st.session_state.history = []

def analyze_link_safety(url):
    risk_score = 0
    reasons = []
    if not url.startswith("https://"):
        risk_score += 3
        reasons.append("⚠️ Weak Protocol: Non-HTTPS")
    if len(url) > 60:
        risk_score += 2
        reasons.append("⚠️ Excessive Length")
    if re.search(r'\d{5,}', url):
        risk_score += 3
        reasons.append("⚠️ Suspicious numeric patterns")
    if any(char in url for char in ['@', '#', '$', '%']):
        risk_score += 2
        reasons.append("⚠️ Suspicious characters")
    status = "Safe" if risk_score < 4 else "High Risk"
    return status, reasons

def generate_pdf(data):
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer)
    p.setFont("Helvetica-Bold", 18)
    p.drawString(100, 820, "CyberSentinel Analysis Report")
    p.setFont("Helvetica-Oblique", 10)
    p.drawString(100, 805, f"Powered by: Shahad Ali Al-Mastour | {pd.Timestamp.now().strftime('%Y-%m-%d')}") 
    p.line(50, 795, 550, 795)
    p.setFont("Helvetica", 12)
    y = 770
    for entry in data:
        p.drawString(50, y, f"URL: {entry['URL']} | Result: {entry['Result']}")
        y -= 20
    p.save()
    buffer.seek(0)
    return buffer

st.title("🛡️ CyberSentinel: Heuristic Security Engine")
url = st.text_input("Enter URL to Analyze:", placeholder="https://example.com")

if st.button("🚀 Run Heuristic Scan"):
    if url:
        status, reasons = analyze_link_safety(url)
        st.session_state.history.append({"URL": url, "Result": status, "Details": ", ".join(reasons)})
        if status == "Safe": st.success(f"Status: {status}")
        else: st.error(f"Status: {status} - Reasons: {'; '.join(reasons)}")
    else: st.warning("Please enter a URL first.")

if st.session_state.history:
    st.write("### 📜 Scan History")
    st.table(pd.DataFrame(st.session_state.history))
    st.download_button("📥 Download Official Report (PDF)", generate_pdf(st.session_state.history), "report.pdf", "application/pdf")

st.markdown("---")
st.caption("© 2026 CyberSentinel | Shahad Ali Al-Mastour")
