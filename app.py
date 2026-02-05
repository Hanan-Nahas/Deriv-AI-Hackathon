"""Streamlit dashboard for secure chat, pentest mode, and logs analytics."""

from __future__ import annotations

import logging
import uuid

import pandas as pd
import streamlit as st

from ai_shield.core.llm_pipeline import LLMPipeline
from ai_shield.core.rag_engine import RAGEngine
from ai_shield.pentest.attack_generator import AttackGenerator
from ai_shield.pentest.report_generator import ReportGenerator
from ai_shield.pentest.vulnerability_analyzer import VulnerabilityAnalyzer
from ai_shield.utils.logging_config import configure_logging
from ai_shield.waf.behavior_monitor import BehaviorMonitor

configure_logging()
logger = logging.getLogger(__name__)

st.set_page_config(page_title="Deriv AI Shield", layout="wide")
st.title("🛡️ Deriv AI Shield Hackathon Demo")

if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "pentest_records" not in st.session_state:
    st.session_state.pentest_records = []

monitor = BehaviorMonitor()
rag_engine = RAGEngine()
rag_engine.add_documents([
    "Deriv AI Shield blocks prompt injection and data exfiltration attacks.",
    "Always validate user input before sending to any language model.",
    "Apply output redaction to avoid leaking keys, passwords, and tokens.",
])
pipeline = LLMPipeline(behavior_monitor=monitor, rag_engine=rag_engine)
attack_generator = AttackGenerator()
analyzer = VulnerabilityAnalyzer()
reporter = ReportGenerator()

tab1, tab2, tab3 = st.tabs(["Secure Chat", "Pentest Mode", "Logs Dashboard"])

with tab1:
    st.subheader("Protected LLM Conversation")
    user_input = st.text_area("Enter your message", height=120)
    if st.button("Send", key="send_btn"):
        response = pipeline.process(user_input=user_input, session_id=st.session_state.session_id)
        st.session_state.chat_history.append(
            {"user": user_input, "assistant": response.text, "blocked": response.blocked, "risk": response.risk_score}
        )

    for i, turn in enumerate(reversed(st.session_state.chat_history), start=1):
        st.markdown(f"**Turn {i}**")
        st.write(f"User: {turn['user']}")
        st.write(f"Assistant: {turn['assistant']}")
        st.caption(f"Blocked: {turn['blocked']} | Risk: {turn['risk']}")

with tab2:
    st.subheader("Autonomous Security Testing")
    count = st.slider("Number of generated attacks", min_value=5, max_value=30, value=10)
    if st.button("Run Pentest", key="pentest_btn"):
        records = []
        for attack in attack_generator.generate(count=count):
            result = pipeline.input_filter.scan(attack.payload)
            monitor.add_event(st.session_state.session_id, attack.category, result.risk_score)
            records.append(analyzer.analyze(attack, result))

        summary = analyzer.aggregate(records)
        markdown_report = reporter.generate_markdown(records, summary)
        html_report = reporter.generate_html(markdown_report)
        paths = reporter.save_reports(markdown_report, html_report)

        st.session_state.pentest_records = records
        st.success("Pentest run completed")
        st.json(summary)
        st.code(markdown_report, language="markdown")
        st.write(f"Saved reports: {paths}")

with tab3:
    st.subheader("Threat and Activity Dashboard")
    summary = monitor.get_session_summary(st.session_state.session_id)
    st.metric("Threat Score", summary.get("threat_score", 0.0))
    st.metric("Events", summary.get("event_count", 0))

    if summary.get("top_attack_types"):
        df = pd.DataFrame(
            [{"Attack Type": key, "Count": val} for key, val in summary["top_attack_types"].items()]
        )
        st.bar_chart(df.set_index("Attack Type"))

    if st.session_state.pentest_records:
        df_records = pd.DataFrame([record.__dict__ for record in st.session_state.pentest_records])
        st.dataframe(df_records)
