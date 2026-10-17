"""Z-AgentShield Operations Console.

Real-Time Security Layer for Enterprise AI Agents.
Streamlit-based SOC console for real-time telemetry, human-in-the-loop triage,
behavioral anomaly insights, and interactive policy simulation.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

# Ensure 'src' is on sys.path so modules import reliably
ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import pandas as pd
import requests
import streamlit as st

from zagentshield.anomalies.detector import AnomalyConfig, AnomalyDetector
from zagentshield.config import get_settings
from zagentshield.core.enums import ActionCategory, ActionVerdict, RiskLevel
from zagentshield.core.models import AgentRequest
from zagentshield.db.database import Database
from zagentshield.db.repository import SecurityRepository
from zagentshield.policies.engine import PolicyEngine

# ---------------------------------------------------------------------------
# Streamlit Page Configuration & Styling
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Z-AgentShield | SOC Operations Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for polished Enterprise SOC Look
st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 0px;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #4B5563;
        margin-bottom: 20px;
    }
    .badge-allow {
        background-color: #D1FAE5;
        color: #065F46;
        padding: 4px 10px;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.85rem;
        display: inline-block;
    }
    .badge-review {
        background-color: #FEF3C7;
        color: #92400E;
        padding: 4px 10px;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.85rem;
        display: inline-block;
    }
    .badge-block {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 4px 10px;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.85rem;
        display: inline-block;
    }
    .card-metric {
        background: #F9FAFB;
        border: 1px solid #E5E7EB;
        padding: 18px;
        border-radius: 10px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_services():
    """Initialize and cache database, repository, policy engine and anomaly detector."""
    settings = get_settings()
    db = Database(settings.database_path)
    db.init_db()
    repo = SecurityRepository(db)
    policy_path = ROOT_DIR / settings.policy_config_path
    if not policy_path.exists():
        policy_path = Path(settings.policy_config_path)

    engine = PolicyEngine.from_yaml_file(
        str(policy_path),
        risk_threshold_review=settings.risk_threshold_review,
        risk_threshold_block=settings.risk_threshold_block,
    )
    detector = AnomalyDetector(config=AnomalyConfig(), repository=repo)
    return db, repo, engine, detector, settings


db, repo, policy_engine, anomaly_detector, settings = get_services()

# ---------------------------------------------------------------------------
# Sidebar: System Health & Configuration
# ---------------------------------------------------------------------------
with st.sidebar:
    st.image(
        "https://raw.githubusercontent.com/tandpfun/skill-icons/main/icons/Shield.svg",
        width=50,
    )
    st.title("Z-AgentShield")
    st.caption("v0.1.0 • Enterprise Edition")
    st.markdown("---")
    st.subheader("System Telemetry")
    try:
        gw_resp = requests.get(f"http://127.0.0.1:{settings.port}/health", timeout=0.8)
        if gw_resp.status_code == 200:
            st.success(f"● Gateway API: ONLINE (:{settings.port})")
        else:
            st.warning(f"▲ Gateway API: HTTP {gw_resp.status_code}")
    except Exception:
        st.warning("○ Gateway API: OFFLINE")
    st.info(f"Target DB: `{Path(settings.database_path).name}`")
    st.markdown(
        f"""
        **Policy Thresholds:**
        - Review Threshold: `{settings.risk_threshold_review}`
        - Block Threshold: `{settings.risk_threshold_block}`
        - Anomaly Window: `{settings.anomaly_window_seconds}s`
        """
    )
    st.markdown("---")
    st.caption("IBM Z Datathon — Enterprise AI Security & Governance Track")
    if st.button("🔄 Refresh Data", use_container_width=True):
        st.rerun()

# ---------------------------------------------------------------------------
# Main Header
# ---------------------------------------------------------------------------
st.markdown('<div class="main-header">🛡️ Z-AgentShield Operations Console</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Real-Time Security Layer for Enterprise AI Agents • <i>Let AI act. Keep every action under control.</i></div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Navigation Tabs
# ---------------------------------------------------------------------------
tab_overview, tab_review, tab_audit, tab_analytics, tab_sim = st.tabs(
    [
        "📊 SOC Overview",
        "🚨 Human-in-the-Loop Triage",
        "📜 Audit Trail",
        "🔍 Behavioral Analytics",
        "⚡ Policy Simulator",
    ]
)

# Fetch latest events
events = repo.list_security_events(limit=500)
tickets = repo.list_review_tickets(limit=200)

# ===========================================================================
# TAB 1: SOC OVERVIEW
# ===========================================================================
with tab_overview:
    st.subheader("Real-Time Telemetry & Threat Metrics")
    
    total_events = len(events)
    allow_count = sum(1 for e in events if e.verdict == "ALLOW")
    review_count = sum(1 for e in events if e.verdict == "REVIEW")
    block_count = sum(1 for e in events if e.verdict == "BLOCK")
    pending_tickets = sum(1 for t in tickets if t.status == "PENDING")
    avg_risk = sum(e.risk_score for e in events) / total_events if total_events > 0 else 0.0

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Interceptions", total_events)
    with col2:
        st.metric("Allowed (Zero-Trust)", allow_count, delta=f"{round(allow_count/total_events*100, 1)}%" if total_events else None)
    with col3:
        st.metric("Review Required", review_count, delta=f"{pending_tickets} Pending", delta_color="inverse")
    with col4:
        st.metric("Blocked Threats", block_count, delta=f"-{block_count} prevented", delta_color="inverse")
    with col5:
        st.metric("Average Risk Score", f"{avg_risk:.1f}/100")

    st.markdown("---")

    col_left, col_right = st.columns([3, 2])
    with col_left:
        st.subheader("Recent Intercepted Agent Actions")
        if events:
            recent_data = []
            for e in events[:10]:
                recent_data.append({
                    "Timestamp": e.timestamp[:19].replace("T", " "),
                    "Agent ID": e.agent_id,
                    "Action": e.action,
                    "Resource": e.resource,
                    "Verdict": e.verdict,
                    "Risk Score": f"{e.risk_score:.1f}",
                    "Level": e.risk_level,
                })
            st.dataframe(pd.DataFrame(recent_data), use_container_width=True, hide_index=True)
        else:
            st.info("No security events intercepted yet. Use the Policy Simulator or Gateway API to start intercepting.")

    with col_right:
        st.subheader("Verdict Distribution")
        if total_events > 0:
            df_dist = pd.DataFrame({
                "Verdict": ["ALLOW", "REVIEW", "BLOCK"],
                "Count": [allow_count, review_count, block_count],
            })
            st.bar_chart(df_dist.set_index("Verdict"))
        else:
            st.info("Awaiting telemetry stream.")

# ===========================================================================
# TAB 2: HUMAN-IN-THE-LOOP TRIAGE (REVIEW QUEUE)
# ===========================================================================
with tab_review:
    st.subheader("🚨 Human-in-the-Loop Approval Queue")
    st.markdown("Review and authorize actions flagged with high risk or policy triggers.")

    status_filter = st.radio(
        "Filter Queue by Status:",
        ["PENDING", "APPROVED", "REJECTED", "ALL"],
        horizontal=True,
    )

    filtered_tickets = tickets
    if status_filter != "ALL":
        filtered_tickets = [t for t in tickets if t.status == status_filter]

    if not filtered_tickets:
        st.success(f"No tickets currently in '{status_filter}' state.")
    else:
        for t in filtered_tickets:
            with st.expander(f"Ticket #{t.ticket_id} — {t.agent_id} ➔ {t.action} on {t.resource} [{t.status}]"):
                c1, c2, c3 = st.columns([2, 2, 2])
                with c1:
                    st.write(f"**Agent ID:** `{t.agent_id}`")
                    st.write(f"**Action:** `{t.action}` ({t.category})")
                    st.write(f"**Resource:** `{t.resource}`")
                with c2:
                    st.write(f"**Risk Score:** `{t.risk_score:.1f}` ({t.risk_level})")
                    st.write(f"**Created:** `{t.created_at[:19].replace('T', ' ')}`")
                    st.write(f"**Current Status:** `{t.status}`")
                with c3:
                    st.write("**Triggered Reasons:**")
                    for r in t.reasons:
                        st.write(f"- {r}")

                if t.reviewer_id:
                    st.info(f"Decided by **{t.reviewer_id}** at {t.updated_at[:19]}: {t.reviewer_notes or 'No notes provided'}")

                if t.status == "PENDING":
                    st.markdown("---")
                    st.write("### Reviewer Action")
                    col_rev_id, col_notes = st.columns([1, 2])
                    with col_rev_id:
                        reviewer_id_input = st.text_input(
                            "Reviewer ID / Certificate",
                            value="sec-officer-admin",
                            key=f"rev_{t.ticket_id}",
                        )
                    with col_notes:
                        notes_input = st.text_input(
                            "Audit / Justification Notes",
                            placeholder="Reason for approval/rejection...",
                            key=f"notes_{t.ticket_id}",
                        )

                    btn_col1, btn_col2, _ = st.columns([1, 1, 4])
                    with btn_col1:
                        if st.button("✅ APPROVE", key=f"app_{t.ticket_id}", type="primary"):
                            try:
                                repo.update_review_status(
                                    ticket_id=t.ticket_id,
                                    new_status="APPROVED",
                                    reviewer_id=reviewer_id_input,
                                    reviewer_notes=notes_input,
                                )
                                st.success(f"Ticket {t.ticket_id} APPROVED.")
                                st.rerun()
                            except Exception as ex:
                                st.error(f"Failed to record decision: {ex}")
                    with btn_col2:
                        if st.button("❌ REJECT", key=f"rej_{t.ticket_id}"):
                            try:
                                repo.update_review_status(
                                    ticket_id=t.ticket_id,
                                    new_status="REJECTED",
                                    reviewer_id=reviewer_id_input,
                                    reviewer_notes=notes_input,
                                )
                                st.warning(f"Ticket {t.ticket_id} REJECTED.")
                                st.rerun()
                            except Exception as ex:
                                st.error(f"Failed to record decision: {ex}")

# ===========================================================================
# TAB 3: AUDIT TRAIL
# ===========================================================================
with tab_audit:
    st.subheader("📜 Immutable Security Audit Trail")
    st.markdown("Cryptographically sanitized and redacted record of all intercepted agent evaluations.")

    col_f1, col_f2, col_f3 = st.columns(3)
    with col_f1:
        verdict_filter = st.selectbox("Filter by Verdict", ["ALL", "ALLOW", "REVIEW", "BLOCK"])
    with col_f2:
        level_filter = st.selectbox("Filter by Risk Level", ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    with col_f3:
        agent_search = st.text_input("Filter by Agent ID", "")

    filtered_events = events
    if verdict_filter != "ALL":
        filtered_events = [e for e in filtered_events if e.verdict == verdict_filter]
    if level_filter != "ALL":
        filtered_events = [e for e in filtered_events if e.risk_level == level_filter]
    if agent_search.strip():
        filtered_events = [e for e in filtered_events if agent_search.lower() in e.agent_id.lower()]

    st.write(f"Displaying **{len(filtered_events)}** matching events.")

    if filtered_events:
        for ev in filtered_events:
            badge_class = f"badge-{ev.verdict.lower()}"
            with st.expander(f"[{ev.verdict}] {ev.timestamp[:19].replace('T', ' ')} — {ev.agent_id} ➔ {ev.action} ({ev.risk_level})"):
                c1, c2 = st.columns(2)
                with c1:
                    st.write(f"**Request ID:** `{ev.request_id}`")
                    st.write(f"**Agent ID:** `{ev.agent_id}`")
                    st.write(f"**Action:** `{ev.action}`")
                    st.write(f"**Category:** `{ev.category}`")
                    st.write(f"**Resource:** `{ev.resource}`")
                with c2:
                    st.write(f"**Verdict:** `{ev.verdict}`")
                    st.write(f"**Risk Score:** `{ev.risk_score:.1f}`")
                    st.write(f"**Risk Level:** `{ev.risk_level}`")
                    st.write(f"**Matched Rules:** `{', '.join(ev.matched_rule_ids) if ev.matched_rule_ids else 'None'}`")

                st.write("**Evaluation Reasons:**")
                for r in ev.reasons:
                    st.write(f"- {r}")

                if ev.parameters_redacted:
                    st.write("**Redacted Parameters Payload:**")
                    st.code(ev.parameters_redacted, language="json")
    else:
        st.info("No audit records match the selected filters.")

# ===========================================================================
# TAB 4: BEHAVIORAL ANALYTICS
# ===========================================================================
with tab_analytics:
    st.subheader("🔍 Behavioral Anomaly & Velocity Analytics")
    st.markdown("Detect velocity bursts, anomalous patterns, and risk drift across autonomous agent fleets.")

    if events:
        df = pd.DataFrame([
            {
                "timestamp": pd.to_datetime(e.timestamp),
                "agent_id": e.agent_id,
                "action": e.action,
                "risk_score": e.risk_score,
                "verdict": e.verdict,
            }
            for e in events
        ])

        col_a1, col_a2 = st.columns(2)
        with col_a1:
            st.write("#### Agent Activity Volume")
            agent_counts = df["agent_id"].value_counts().reset_index()
            agent_counts.columns = ["Agent ID", "Interceptions"]
            st.bar_chart(agent_counts.set_index("Agent ID"))

        with col_a2:
            st.write("#### Risk Score Distribution")
            st.scatter_chart(df, x="timestamp", y="risk_score", color="verdict")

        st.write("#### Burst Velocity & Threat Detection")
        agent_options = list(df["agent_id"].unique())
        selected_agent = st.selectbox("Inspect Agent Behavioral Profile:", agent_options)
        if selected_agent:
            agent_events = [e for e in events if e.agent_id == selected_agent]
            st.write(f"Total requests by `{selected_agent}`: **{len(agent_events)}**")
            high_risk_ops = [e for e in agent_events if e.risk_score >= settings.risk_threshold_review]
            if high_risk_ops:
                st.warning(f"⚠️ Flagged **{len(high_risk_ops)}** elevated or high-risk operations for `{selected_agent}`.")
            else:
                st.success(f"✅ `{selected_agent}` operates within safe baseline parameters.")
    else:
        st.info("Insufficient data for behavioral analytics. Run live queries to view telemetry.")

# ===========================================================================
# TAB 5: POLICY SIMULATOR
# ===========================================================================
with tab_sim:
    st.subheader("⚡ Real-Time Policy Simulation Playground")
    st.markdown("Test an agent action payload against active enterprise policies before deployment.")

    with st.form("simulation_form"):
        sim_col1, sim_col2 = st.columns(2)
        with sim_col1:
            sim_agent_id = st.text_input("Agent ID", "agent-financial-bot-01")
            sim_action = st.text_input("Action Name", "export_customer_data")
            sim_category = st.selectbox("Category", [c.value for c in ActionCategory], index=3)
            sim_resource = st.text_input("Target Resource", "db://customers/financial_records")

        with sim_col2:
            sim_perms = st.text_input("Claimed Permissions (comma-separated)", "read.data, export.data")
            sim_params = st.text_area("Parameters (JSON)", '{\n  "records": 50000,\n  "format": "csv",\n  "api_key": "sk-live-998877665544"\n}', height=105)

        submitted = st.form_submit_button("🛡️ Simulate Interception Evaluation", type="primary")

    if submitted:
        try:
            parsed_params = json.loads(sim_params) if sim_params.strip() else {}
        except Exception:
            parsed_params = {"raw": sim_params}

        perms_list = [p.strip() for p in sim_perms.split(",") if p.strip()]

        sim_request = AgentRequest(
            agent_id=sim_agent_id,
            action=sim_action,
            category=ActionCategory(sim_category),
            resource=sim_resource,
            parameters=parsed_params,
            claimed_permissions=perms_list,
        )

        evaluation = policy_engine.evaluate(sim_request)

        st.markdown("---")
        st.subheader("Simulation Results")
        res_col1, res_col2, res_col3 = st.columns(3)
        with res_col1:
            st.metric("Final Verdict", evaluation.verdict.value)
        with res_col2:
            st.metric("Evaluated Risk Score", f"{evaluation.risk_score:.1f}/100")
        with res_col3:
            st.metric("Risk Severity", evaluation.risk_level.value)

        st.write("**Evaluation Breakdown & Reasons:**")
        for reason in evaluation.reasons:
            st.markdown(f"- {reason}")

        if evaluation.matched_rule_ids:
            st.write(f"**Matched Policy Rules:** `{', '.join(evaluation.matched_rule_ids)}`")

        if evaluation.verdict == ActionVerdict.ALLOW:
            st.success("✅ Action GRANTED execution permission.")
        elif evaluation.verdict == ActionVerdict.REVIEW:
            st.warning("⚠️ Action ESCALATED to Human-in-the-Loop review queue.")
        else:
            st.error("🛑 Action BLOCKED by security boundary.")
