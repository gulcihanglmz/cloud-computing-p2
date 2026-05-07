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
    .main {
        background: radial-gradient(circle at top, rgba(255, 75, 75, 0.14), transparent 30%), linear-gradient(180deg, #0b1020 0%, #0e1117 55%, #0b0f18 100%);
        color: #ffffff;
    }
    .block-container { padding-top: 2rem; padding-bottom: 2rem; }
    h1, h2, h3 { letter-spacing: -0.02em; }
    .hero-shell {
        background: linear-gradient(135deg, rgba(255, 75, 75, 0.14), rgba(30, 144, 255, 0.10));
        border: 1px solid rgba(255, 255, 255, 0.10);
        border-radius: 22px;
        padding: 1.6rem 1.8rem;
        box-shadow: 0 18px 50px rgba(0, 0, 0, 0.25);
        margin-bottom: 1.2rem;
    }
    .hero-title { font-size: 2.1rem; font-weight: 800; margin-bottom: 0.4rem; }
    .hero-subtitle { color: #d7deea; font-size: 1.02rem; line-height: 1.6; margin-bottom: 0.9rem; }
    .pill-row { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.4rem; }
    .pill {
        display: inline-block;
        padding: 0.42rem 0.7rem;
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.08);
        border: 1px solid rgba(255, 255, 255, 0.12);
        color: #f2f5fb;
        font-size: 0.82rem;
    }
    .section-card {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 18px;
        padding: 1rem 1.1rem;
        height: 100%;
        box-shadow: 0 12px 28px rgba(0, 0, 0, 0.16);
    }
    .section-label { color: #8fb7ff; font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.35rem; }
    .section-title { font-size: 1.02rem; font-weight: 700; margin-bottom: 0.25rem; }
    .section-text { color: #c8d2e2; font-size: 0.92rem; line-height: 1.5; }
    .metric-card {
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.05), rgba(255, 255, 255, 0.03));
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 18px;
        padding: 1rem 1.1rem;
        box-shadow: 0 12px 30px rgba(0, 0, 0, 0.18);
    }
    .metric-label { font-size: 0.78rem; color: #9aa7bc; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 0.35rem; }
    .metric-value { font-size: 1.7rem; font-weight: 800; line-height: 1.1; margin-bottom: 0.2rem; }
    .metric-note { color: #c7d0dd; font-size: 0.9rem; }
    .stTextArea textarea { font-family: monospace; background-color: #1e2129; color: white; border: 1px solid #4b4b4b; }
    .stButton button { background: linear-gradient(135deg, #ff4b4b, #ff7a45); color: white; width: 100%; font-weight: 700; border: none; border-radius: 12px; padding: 0.7rem 1rem; }
    .stButton button:hover { transform: translateY(-1px); box-shadow: 0 10px 22px rgba(255, 75, 75, 0.25); }
    .report-box { background-color: #1e2129; padding: 20px; border-radius: 14px; border: 1px solid #4b4b4b; margin-bottom: 20px; box-shadow: 0 10px 24px rgba(0, 0, 0, 0.16); }
    .report-header { font-size: 24px; font-weight: bold; color: #ff4b4b; margin-bottom: 10px; }
    .report-subheader { font-size: 18px; font-weight: bold; color: #1e90ff; margin-top: 15px; margin-bottom: 5px; border-bottom: 1px solid #4b4b4b; padding-bottom: 5px;}
    .recommendation { background-color: #2a2a3e; padding: 10px; border-radius: 5px; margin-top: 10px; border-left: 5px solid #ff4b4b;}
    .summary-strip {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 16px;
        padding: 0.9rem 1rem;
        margin-bottom: 1rem;
        color: #d8e0ec;
    }
    </style>
    """, unsafe_allow_html=True)

# --- PRE-DEFINED SCENARIOS ---
# The trained model expects numeric syscall IDs, so the demo presets use the same format.
DEMO_PRESETS = {
    "Manual Input": {
        "trace": "",
        "risk_note": "Type your own syscall ID sequence"
    },
    "Normal Container Activity": {
        "trace": "15",
        "risk_note": "Expected to stay in the low-risk range"
    },
    "File and Process Activity": {
        "trace": "61 0",
        "risk_note": "Usually lands in the medium-risk range"
    },
    "Suspicious Access Pattern": {
        "trace": "0",
        "risk_note": "Usually lands in the high-risk range"
    },
    "Critical Escape Pattern": {
        "trace": "13 0 33",
        "risk_note": "Usually lands in the critical-risk range"
    }
}

# --- LOAD ARTIFACTS ---
@st.cache_resource
def load_artifacts():
    vectorizer_candidates = [
        os.path.join('artifacts', 'vectorizer.pkl'),
        os.path.join('artifacts', 'system_calls_vectorizer.joblib')
    ]
    model_candidates = [
        os.path.join('artifacts', 'best_model.pkl'),
        os.path.join('artifacts', 'best_model.joblib'),
        os.path.join('artifacts', 'model.pkl')
    ]

    try:
        vectorizer = None
        for vectorizer_path in vectorizer_candidates:
            if os.path.exists(vectorizer_path):
                vectorizer = joblib.load(vectorizer_path)
                break

        if vectorizer is None:
            return None, None

        expected_features = len(getattr(vectorizer, 'vocabulary_', {}))

        for model_path in model_candidates:
            if not os.path.exists(model_path):
                continue

            model = joblib.load(model_path)
            if getattr(model, 'n_features_in_', expected_features) == expected_features:
                return model, vectorizer

        return joblib.load(model_candidates[0]) if os.path.exists(model_candidates[0]) else None, vectorizer
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

NUMERIC_SIGNAL_PATTERNS = {
    "Baseline I/O": {
        "syscalls": ["0", "1", "3", "8", "15"],
        "description": "Basic file and buffer activity",
        "impact": "LOW"
    },
    "Process and Signal Handling": {
        "syscalls": ["13", "14", "33", "61", "72"],
        "description": "Process coordination and signal-related behavior",
        "impact": "MEDIUM"
    },
    "Identity and Privilege Checks": {
        "syscalls": ["21", "102", "104", "107", "108"],
        "description": "Identity and permission-related activity",
        "impact": "HIGH"
    },
    "Filesystem and Namespace Actions": {
        "syscalls": ["16", "56", "257", "262"],
        "description": "Filesystem or namespace-heavy behavior",
        "impact": "CRITICAL"
    }
}

def generate_security_report(prediction, probability, system_calls):
    # Basit bir rapor üretici
    pred_label = "UNSAFE" if prediction == 1 else "SAFE"
    risk_level = "LOW"
    if probability >= 0.75: risk_level = "CRITICAL"
    elif probability >= 0.50: risk_level = "HIGH"
    elif probability >= 0.25: risk_level = "MEDIUM"
    
    calls_list = [call for call in system_calls.lower().replace(',', ' ').split() if call]
    detected_patterns = []
    is_numeric_trace = all(call.isdigit() for call in calls_list)

    pattern_source = NUMERIC_SIGNAL_PATTERNS if is_numeric_trace else ATTACK_PATTERNS
    for pattern_name, details in pattern_source.items():
        matched = [call for call in calls_list if call in details["syscalls"]]
        if matched:
            detected_patterns.append({
                "type": pattern_name,
                "calls": matched,
                "impact": details["impact"],
                "description": details.get("description", "Behavior pattern matched")
            })
            
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

st.markdown("""
<div class="hero-shell">
    <div class="hero-title">Detect suspicious Docker behavior from syscall traces</div>
    <div class="hero-subtitle">
        This demo turns raw system-call logs into a risk score, a plain-language explanation, and a visual security summary.
        It is built to show how container escape and privilege-escalation behavior can be spotted before damage spreads.
        The trained model uses numeric syscall IDs, so the demo presets below use the same format.
    </div>
    <div class="pill-row">
        <span class="pill">Real-time syscall analysis</span>
        <span class="pill">Container escape monitoring</span>
        <span class="pill">Risk scoring + explanation</span>
        <span class="pill">Presentation-friendly dashboard</span>
    </div>
</div>
""", unsafe_allow_html=True)

overview_col1, overview_col2, overview_col3 = st.columns(3)
with overview_col1:
    st.markdown("""
    <div class="metric-card">
        <div class="metric-label">Input</div>
        <div class="metric-value">Syscall trace</div>
        <div class="metric-note">Paste a sequence or use a sample scenario.</div>
    </div>
    """, unsafe_allow_html=True)
with overview_col2:
    st.markdown("""
    <div class="metric-card">
        <div class="metric-label">Analysis</div>
        <div class="metric-value">ML + rules</div>
        <div class="metric-note">Combines model prediction with attack-pattern hints.</div>
    </div>
    """, unsafe_allow_html=True)
with overview_col3:
    st.markdown("""
    <div class="metric-card">
        <div class="metric-label">Output</div>
        <div class="metric-value">Risk score</div>
        <div class="metric-note">Shows safe, suspicious, or critical behavior.</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("""
<div class="summary-strip">
    <strong>How it works:</strong> choose a sample or enter your own trace, run the analysis, then read the risk meter, the status cards, and the final JSON object.
</div>
""", unsafe_allow_html=True)

if model and vectorizer:
    col_in, col_bench = st.columns([2, 1])
    with col_in:
        st.subheader("Step 1 - Enter a syscall trace")
        st.caption("Choose a sample to auto-fill the box, or paste your own syscall ID sequence in the same format.")

        st.markdown("""
        <div class="section-card">
            <div class="section-label">Quick guide</div>
            <div class="section-title">1. Pick a demo preset</div>
            <div class="section-text">This fills the box with a trace that the model understands and maps to a risk band.</div>
            <div class="section-title" style="margin-top:0.7rem;">2. Edit or paste your own trace</div>
            <div class="section-text">Use space- or comma-separated syscall IDs, then run the analysis.</div>
        </div>
        """, unsafe_allow_html=True)

        selected_scenario = st.selectbox("Demo preset", list(DEMO_PRESETS.keys()), help="Choose a ready-made example or switch to Manual Input.")
        st.caption(f"{selected_scenario}: {DEMO_PRESETS[selected_scenario]['risk_note']}")
        log_input = st.text_area(
            "Syscall ID trace",
            value=DEMO_PRESETS[selected_scenario]["trace"],
            height=120,
            placeholder="Example: 15 61 0 13 33",
            help="Paste syscall IDs separated by spaces or commas. These are the tokens the model was trained on."
        )
        analyze_btn = st.button("Analyze trace")
    
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
            k1, k2, k3 = st.columns(3)
            with k1:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-label">Prediction</div>
                    <div class="metric-value">{report['status']}</div>
                    <div class="metric-note">The model sees this trace as {'unsafe' if prediction == 1 else 'safe'}.</div>
                </div>
                """, unsafe_allow_html=True)
            with k2:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-label">Risk Score</div>
                    <div class="metric-value">{probability*100:.2f}%</div>
                    <div class="metric-note">Higher values indicate stronger attack-like behavior.</div>
                </div>
                """, unsafe_allow_html=True)
            with k3:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-label">Patterns Found</div>
                    <div class="metric-value">{len(report['patterns'])}</div>
                    <div class="metric-note">Rule-based clues matched in the trace.</div>
                </div>
                """, unsafe_allow_html=True)

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

            if report['patterns']:
                st.markdown("### Why it was flagged")
                for pattern in report['patterns']:
                    st.markdown(f"""
                    <div class="section-card">
                        <div class="section-label">{pattern['type']}</div>
                        <div class="section-title">Matched calls: {', '.join(pattern['calls'])}</div>
                        <div class="section-text">This pattern is often linked to {pattern['impact'].lower()} security events in container environments.</div>
                    </div>
                    """, unsafe_allow_html=True)

            # --- JSON OUTPUT (Geri Eklenen Kısım) ---
            st.subheader("Final Prediction Object")
            st.json({
                "label": report['status'],
                "risk_score": round(probability * 100, 2),
                "risk_level": report['risk'],
                "attack_types": [p['type'] for p in report['patterns']] if report['patterns'] else ["None"],
                "prediction_confidence": round(probability if prediction == 1 else 1-probability, 4),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "syscall_count": len(cleaned_input.split())
            })
else:
    st.error("Artifacts missing. Check 'artifacts/' folder.")