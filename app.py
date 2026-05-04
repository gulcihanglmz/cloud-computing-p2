import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import time
import plotly.graph_objects as go
import plotly.express as px
from sklearn.feature_extraction.text import CountVectorizer

# --- UI CONFIGURATION ---
st.set_page_config(page_title="Syscall Forensic Analyzer: Real-Time Docker Intrusion & Escape Monitoring", layout="wide")

# Custom CSS for dark SOC theme
st.markdown("""
    <style>
    .main { background-color: #0e1117; color: #ffffff; }
    .stTextArea textarea { font-family: monospace; background-color: #1e2129; color: white; border: 1px solid #4b4b4b; }
    .stButton button { background-color: #ff4b4b; color: white; width: 100%; font-weight: bold; }
    .report-box { background-color: #1e2129; padding: 20px; border-radius: 10px; border: 1px solid #4b4b4b; margin-bottom: 20px; }
    .report-header { font-size: 24px; font-weight: bold; color: #ff4b4b; margin-bottom: 10px; }
    .report-subheader { font-size: 18px; font-weight: bold; color: #1e90ff; margin-top: 15px; margin-bottom: 5px; border-bottom: 1px solid #4b4b4b; padding-bottom: 5px;}
    .recommendation { background-color: #2a2a3e; padding: 10px; border-radius: 5px; margin-top: 10px; border-left: 5px solid #ff4b4b;}
    </style>
    """, unsafe_allow_html=True)

# --- PRE-DEFINED SCENARIOS ---
SCENARIOS = {
    "Manual Input": "",
    "Normal Container Activity": "open, read, write, close, fstat, mmap, brk, futex, getuid",
    "Container Escape (Mount Attempt)": "open, mount, unshare, setns, pivot_root, write, close",
    "Privilege Escalation (Root Seek)": "ptrace, setuid, setgid, capset, execve, open, read",
    "Network Reconnaissance": "socket, connect, sendto, recvfrom, bind, listen, accept",
    "Suspicious Process Injection": "clone, ptrace, process_vm_writev, mprotect, execve"
}

# --- LOAD ARTIFACTS ---
@st.cache_resource
def load_artifacts():
    try:
        model = joblib.load(os.path.join('artifacts', 'model.pkl'))
        vectorizer = joblib.load(os.path.join('artifacts', 'vectorizer.pkl'))
        return model, vectorizer
    except:
        return None, None

model, vectorizer = load_artifacts()

# --- ANALYSIS & REPORTING ENGINE ---
ATTACK_PATTERNS = {
    "Privilege Escalation": {"syscalls": ["ptrace", "setuid", "setgid", "capset", "prctl", "seteuid", "setegid"], "impact": "CRITICAL"},
    "Container Escape": {"syscalls": ["mount", "umount", "unshare", "clone", "setns", "pivot_root"], "impact": "CRITICAL"},
    "Lateral Movement": {"syscalls": ["socket", "connect", "sendto", "recvfrom", "listen", "bind", "accept"], "impact": "HIGH"},
    "Reconnaissance": {"syscalls": ["open", "read", "stat", "getuid", "gethostname", "uname"], "impact": "MEDIUM"}
}

def generate_security_report(prediction, probability, system_calls):
    # Basit bir rapor üretici
    pred_label = "UNSAFE" if prediction == 1 else "SAFE"
    risk_level = "LOW"
    if probability >= 0.75: risk_level = "CRITICAL"
    elif probability >= 0.50: risk_level = "HIGH"
    elif probability >= 0.25: risk_level = "MEDIUM"
    
    calls_list = system_calls.lower().split()
    detected_patterns = []
    for attack, details in ATTACK_PATTERNS.items():
        matched = [c for c in calls_list if c in details["syscalls"]]
        if matched:
            detected_patterns.append({"type": attack, "calls": matched, "impact": details["impact"]})
            
    return {"status": pred_label, "risk": risk_level, "prob": probability, "patterns": detected_patterns}

# --- VISUALIZATION ---
def draw_gauge(prob, risk_level):
    color = {"CRITICAL": "red", "HIGH": "orange", "MEDIUM": "yellow", "LOW": "green"}.get(risk_level, "green")
    fig = go.Figure(go.Indicator(
        mode = "gauge+number", value = prob * 100,
        title = {'text': f"Threat Level: {risk_level}", 'font': {'color': color}},
        gauge = {'axis': {'range': [0, 100]}, 'bar': {'color': color}}
    ))
    fig.update_layout(height=300, paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"})
    return fig

# --- MAIN UI ---
st.title("Syscall Forensic Analyzer: Real-Time Docker Intrusion & Escape Monitoring")

if model and vectorizer:
    col_in, col_bench = st.columns([2, 1])
    with col_in:
        st.subheader("Analysis Configuration")
        selected_scenario = st.selectbox("Select scenario:", list(SCENARIOS.keys()))
        log_input = st.text_area("Syscall Logs:", value=SCENARIOS[selected_scenario], height=100)
        analyze_btn = st.button("Run Security Analysis")
    
    if analyze_btn:
        cleaned_input = log_input.replace(',', ' ')
        with st.spinner('Analyzing...'):
            # Prediction
            input_vector = vectorizer.transform([cleaned_input])
            prediction = model.predict(input_vector)[0]
            probability = model.predict_proba(input_vector)[0][1]
            
            report = generate_security_report(prediction, probability, cleaned_input)

            # --- DISPLAY DASHBOARD ---
            st.divider()
            r1, r2, r3 = st.columns([1.5, 1, 1])
            with r1:
                st.plotly_chart(draw_gauge(probability, report['risk']), use_container_width=True)
            with r2:
                st.metric("Status", report['status'], delta="- Unsafe" if prediction == 1 else "Secure", delta_color="inverse")
                st.metric("Probability", f"{probability*100:.2f}%")
            with r3:
                calls = cleaned_input.split()
                fig_pie = px.pie(pd.Series(calls).value_counts().reset_index(), values='count', names='index', hole=.4, title="Syscall Distribution")
                st.plotly_chart(fig_pie, use_container_width=True)

            # --- REPORT BOX ---
            st.markdown(f"""
            <div class="report-box">
                <div class="report-header">Security Analysis Report</div>
                <p><b>Assessment:</b> {report['status']} - {report['risk']} Risk</p>
                <p><b>Detected Attack Patterns:</b> {len(report['patterns'])} found.</p>
            </div>
            """, unsafe_allow_html=True)

            # --- JSON OUTPUT (Geri Eklenen Kısım) ---
            st.subheader("Final Prediction Object")
            st.json({
                "label": report['status'],
                "risk_score": round(probability * 100, 2),
                "risk_level": report['risk'],
                "attack_types": [p['type'] for p in report['patterns']] if report['patterns'] else ["None"],
                "confidence": round(probability if prediction == 1 else 1-probability, 4),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "syscall_count": len(cleaned_input.split())
            })
else:
    st.error("Artifacts missing. Check 'artifacts/' folder.")