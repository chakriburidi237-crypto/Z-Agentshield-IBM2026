"""Z-AgentShield enterprise security operations dashboard."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import uuid

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import pandas as pd
import requests
import streamlit as st
from pydantic import ValidationError

from zagentshield.audit.redaction import redact_sensitive_data
from zagentshield.config import get_settings
from zagentshield.core.enums import ActionCategory, ActionVerdict
from zagentshield.core.models import AgentRequest
from zagentshield.db.database import Database
from zagentshield.db.repository import SecurityRepository
from zagentshield.policies.engine import PolicyEngine


PAGE_SIZE = 25
MAX_ANALYTICS_EVENTS = 500
SECTIONS = (
    "SOC overview",
    "Human review",
    "Audit trail",
    "Behavioral analytics",
    "Policy simulator",
)
WINDOWS = {
    "24 hours": timedelta(hours=24),
    "7 days": timedelta(days=7),
    "30 days": timedelta(days=30),
    "All history": None,
}

st.set_page_config(
    page_title="Z-AgentShield | Security Operations",
    page_icon=str(ROOT_DIR / "assets" / "images" / "zagentshield-mark.svg"),
    layout="wide",
    initial_sidebar_state="auto",
)


@st.cache_resource
def get_services():
    """Initialize and cache the configured database and policy services."""
    settings = get_settings()
    database = Database(settings.database_path)
    database.init_db()
    repository = SecurityRepository(database)
    policy_path = Path(settings.policy_config_path)
    if not policy_path.is_absolute():
        policy_path = ROOT_DIR / policy_path
    engine = PolicyEngine.from_yaml_file(
        str(policy_path),
        risk_threshold_review=settings.risk_threshold_review,
        risk_threshold_block=settings.risk_threshold_block,
    )
    return database, repository, engine, settings


def display_text(value: object) -> str:
    """Apply project redaction before rendering persisted text."""
    return str(redact_sensitive_data(value))


def as_utc_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def pagination_controls(key: str, total: int, page_size: int) -> int:
    """Render bounded previous/next controls and return the SQL offset."""
    page_count = max(1, (total + page_size - 1) // page_size)
    state_key = f"{key}_page"
    page = min(st.session_state.get(state_key, 0), page_count - 1)
    st.session_state[state_key] = page
    previous, status, following = st.columns([1, 3, 1], vertical_alignment="center")
    if previous.button(
        "Previous",
        key=f"{key}_previous",
        disabled=page == 0,
        icon=":material/arrow_back:",
    ):
        st.session_state[state_key] -= 1
        st.rerun()
    status.caption(f"Page {page + 1} of {page_count} · {total:,} records")
    if following.button(
        "Next",
        key=f"{key}_next",
        disabled=page >= page_count - 1,
        icon=":material/arrow_forward:",
    ):
        st.session_state[state_key] += 1
        st.rerun()
    return page * page_size


try:
    database, repository, policy_engine, settings = get_services()
except Exception as exc:
    st.title("Z-AgentShield")
    st.error(
        "The configured database or policy service could not be initialized. "
        f"Review the local configuration and service logs. ({type(exc).__name__})",
        title="Dashboard initialization failed",
    )
    st.stop()

gateway_url = f"http://127.0.0.1:{settings.port}"
health_checked_at = datetime.now(timezone.utc)
gateway_healthy = False
gateway_state = "Unavailable"
try:
    health_response = requests.get(f"{gateway_url}/health", timeout=1.5)
    if health_response.status_code == 200:
        health_payload = health_response.json()
        gateway_healthy = (
            isinstance(health_payload, dict)
            and health_payload.get("status") == "ok"
            and bool(health_payload.get("version"))
        )
        gateway_state = "Healthy" if gateway_healthy else "Degraded"
    else:
        gateway_state = "Degraded"
except (requests.RequestException, ValueError):
    gateway_state = "Unavailable"

try:
    with database.connection() as connection:
        connection.execute("SELECT 1 FROM security_events LIMIT 0").fetchall()
        connection.execute("SELECT 1 FROM review_queue LIMIT 0").fetchall()
    database_state = "Healthy"
    database_error = None
except Exception as exc:
    database_state = "Unavailable"
    database_error = type(exc).__name__

if gateway_healthy:
    st.session_state["gateway_last_success"] = health_checked_at.isoformat()
last_gateway_success = st.session_state.get("gateway_last_success")

with st.sidebar:
    st.image(
        str(ROOT_DIR / "assets" / "images" / "zagentshield-mark.svg"),
        width=58,
    )
    st.title("Z-AgentShield")
    st.caption("Enterprise AI Security")
    st.divider()
    st.subheader("System health")
    if gateway_state == "Healthy":
        st.success(f"Gateway live health: {gateway_state}")
    elif gateway_state == "Degraded":
        st.warning(f"Gateway live health: {gateway_state}")
    else:
        st.error(f"Gateway live health: {gateway_state}")
    st.caption(f"Health endpoint checked: {health_checked_at:%Y-%m-%d %H:%M:%S UTC}")
    st.caption(
        "Last successful check: "
        + (
            datetime.fromisoformat(last_gateway_success).strftime("%Y-%m-%d %H:%M:%S UTC")
            if last_gateway_success
            else "None recorded in this dashboard session"
        )
    )
    if database_state == "Healthy":
        st.success("Configured SQLite database query: Healthy")
    else:
        st.error(
            f"Configured SQLite database query: {database_state} ({database_error})"
        )
    st.caption(f"Database file: {Path(settings.database_path).name}")
    st.caption("Policies are loaded from the configured YAML file.")
    if st.button("Refresh data", icon=":material/refresh:", width="stretch"):
        st.rerun()

header, diagram = st.columns([3, 2], vertical_alignment="center")
with header:
    st.title("Security operations")
    st.caption("Real-time security layer for enterprise AI agents.")
    st.markdown("*Let AI act. Keep every action under control.*")
with diagram:
    st.image(
        str(ROOT_DIR / "assets" / "images" / "security-flow.svg"),
        width="stretch",
    )
    st.caption("Agent request → gateway → policy → ALLOW / REVIEW / BLOCK → audit")

st.caption(
    "Historical data source: configured SQLite database. The schema does not "
    "identify whether stored events are operational or synthetic."
)
section = st.selectbox(
    "Dashboard section",
    SECTIONS,
    key="dashboard_section",
)

now = datetime.now(timezone.utc)

if section == "SOC overview":
    st.subheader("Security operations overview")
    window_label = st.selectbox(
        "Event time window",
        tuple(WINDOWS),
        index=1,
        key="overview_window",
    )
    window_duration = WINDOWS[window_label]
    window_start = now - window_duration if window_duration else None
    since_iso = as_utc_iso(window_start) if window_start else None

    try:
        summary = repository.get_event_summary(since_iso=since_iso)
        pending_total = repository.count_pending_reviews()
        recent_events = repository.list_security_events(
            limit=10,
            since_iso=since_iso,
        )
        recent_blocks = repository.list_security_events(
            limit=10,
            since_iso=since_iso,
            verdict=ActionVerdict.BLOCK.value,
        )
    except Exception as exc:
        st.error(
            f"Unable to load persisted security metrics ({type(exc).__name__}).",
            title="Database query failed",
        )
        st.stop()

    st.caption(
        f"Source: persisted SQLite events and review queue · Window: {window_label}"
    )
    if summary["average_risk"] is None:
        st.caption("Average risk is unavailable because there are no events in this window.")
    if window_start:
        st.caption(f"Window starts {window_start:%Y-%m-%d %H:%M UTC}.")

    metric_columns = st.columns(3)
    metrics = (
        ("Recorded events", summary["total"]),
        ("ALLOW", summary["allow"]),
        ("REVIEW", summary["review"]),
    )
    for column, (label, value) in zip(metric_columns, metrics):
        with column:
            st.metric(label, f"{value:,}")
    metric_columns = st.columns(3)
    for column, (label, value) in zip(
        metric_columns,
        (
            ("BLOCK", summary["block"]),
            ("Pending reviews", pending_total),
            (
                "Average risk score",
                f'{summary["average_risk"]:.1f}/100'
                if summary["average_risk"] is not None
                else "N/A",
            ),
        ),
    ):
        with column:
            st.metric(label, value)

    health_columns = st.columns(2)
    with health_columns[0]:
        with st.container(border=True):
            st.markdown("**Gateway health**")
            st.write(gateway_state)
            st.caption(f"Last checked: {health_checked_at:%Y-%m-%d %H:%M:%S UTC}")
    with health_columns[1]:
        with st.container(border=True):
            st.markdown("**Database health**")
            st.write(database_state)
            st.caption(
                "Latest event: "
                + (
                    display_text(summary["latest_event_at"])
                    if summary["latest_event_at"]
                    else "No persisted event in this window"
                )
            )

    st.subheader("Recent security events")
    if recent_events:
        table = [
            {
                "Timestamp (UTC)": display_text(event.timestamp),
                "Decision": event.verdict,
                "Agent": display_text(event.agent_id),
                "Action": display_text(event.action),
                "Risk": f"{event.risk_score:.1f} · {event.risk_level}",
            }
            for event in recent_events
        ]
        st.dataframe(pd.DataFrame(table), hide_index=True, width="stretch")
    else:
        st.info(f"No persisted security events in the selected {window_label.lower()} window.")

    st.subheader("Recent policy violations")
    st.caption(
        "Defined here as recent BLOCK decisions; this is historical policy output, "
        "not a claim that a downstream operation was attempted or prevented."
    )
    if recent_blocks:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Timestamp (UTC)": display_text(event.timestamp),
                        "Agent": display_text(event.agent_id),
                        "Action": display_text(event.action),
                        "Risk": f"{event.risk_score:.1f} · {event.risk_level}",
                        "Matched rules": ", ".join(event.matched_rule_ids) or "Unavailable",
                    }
                    for event in recent_blocks
                ]
            ),
            hide_index=True,
            width="stretch",
        )
    else:
        st.info("No BLOCK decisions were recorded in the selected window.")

    if not gateway_healthy:
        st.warning(
            "The gateway health endpoint did not confirm a healthy service. "
            "Database-backed history may still be available.",
            title="Gateway is not healthy",
        )

elif section == "Human review":
    st.subheader("Human review queue")
    st.caption("Source: persisted pending tickets · Review actions are read-only.")
    filter_columns = st.columns(2)
    agent_filter = filter_columns[0].text_input(
        "Filter by agent ID",
        key="review_agent_filter",
    )
    risk_filter = filter_columns[1].selectbox(
        "Risk level",
        ("All", "LOW", "MEDIUM", "HIGH", "CRITICAL"),
        key="review_risk_filter",
    )
    selected_risk = None if risk_filter == "All" else risk_filter
    try:
        ticket_total = repository.count_pending_reviews(
            agent_id=agent_filter.strip() or None,
            risk_level=selected_risk,
        )
        ticket_offset = pagination_controls("review_queue", ticket_total, PAGE_SIZE)
        tickets = repository.list_pending_reviews(
            limit=PAGE_SIZE,
            offset=ticket_offset,
            agent_id=agent_filter.strip() or None,
            risk_level=selected_risk,
        )
    except Exception as exc:
        st.error(
            f"Unable to load the pending review queue ({type(exc).__name__}).",
            title="Review queue unavailable",
        )
        tickets = []
        ticket_total = 0

    if ticket_total == 0:
        st.info("No pending review tickets match the selected filters.")
    else:
        for ticket in tickets:
            with st.container(border=True):
                st.markdown(
                    f"**{display_text(ticket.action)}** · "
                    f"{ticket.risk_score:.1f}/100 · "
                    f"{display_text(ticket.risk_level)} risk"
                )
                details = st.columns(3)
                details[0].markdown(
                    f"**Request ID**  \n`{display_text(ticket.request_id)}`"
                )
                details[1].markdown(
                    f"**Agent**  \n`{display_text(ticket.agent_id)}`"
                )
                details[2].markdown(
                    f"**Created (UTC)**  \n{display_text(ticket.created_at)}"
                )
                st.write(f"**Decision status:** {display_text(ticket.status)}")
                st.write(
                    "**Requested resource (unverified):** "
                    f"`{display_text(ticket.resource)}`"
                )
                st.write("**Decision reasons:**")
                for reason in ticket.reasons:
                    st.write(f"- {display_text(reason)}")
                st.caption(
                    "Request parameter payloads are not available in this view. "
                    "Credentials and sensitive request content are not displayed."
                )

    st.warning(
        "Approval and rejection controls are unavailable. This project does not "
        "integrate trusted reviewer authentication and authorization; "
        "X-Reviewer-Id alone is not proof of identity.",
        title="Review actions disabled",
    )

elif section == "Audit trail":
    st.subheader("Audit trail")
    st.caption(
        "Source: persisted SQLite security events. Audit records are not "
        "cryptographically immutable; request parameter payloads are omitted."
    )
    controls = st.columns(3)
    audit_window_label = controls[0].selectbox(
        "Time window",
        tuple(WINDOWS),
        index=2,
        key="audit_window",
    )
    verdict_filter = controls[1].selectbox(
        "Decision",
        ("All", "ALLOW", "REVIEW", "BLOCK"),
        key="audit_verdict",
    )
    agent_filter = controls[2].text_input(
        "Agent ID contains",
        key="audit_agent",
    )
    audit_duration = WINDOWS[audit_window_label]
    audit_start = now - audit_duration if audit_duration else None
    audit_since = as_utc_iso(audit_start) if audit_start else None
    audit_verdict = None if verdict_filter == "All" else verdict_filter
    audit_agent = agent_filter.strip() or None
    try:
        audit_total = repository.count_security_events(
            since_iso=audit_since,
            verdict=audit_verdict,
            agent_id=audit_agent,
        )
        audit_offset = pagination_controls("audit_events", audit_total, PAGE_SIZE)
        audit_events = repository.list_security_events(
            limit=PAGE_SIZE,
            offset=audit_offset,
            since_iso=audit_since,
            verdict=audit_verdict,
            agent_id=audit_agent,
        )
    except Exception as exc:
        st.error(
            f"Unable to query persisted audit records ({type(exc).__name__}).",
            title="Audit trail unavailable",
        )
        audit_events = []
        audit_total = 0

    if not audit_events:
        st.info("No audit records match the selected filters.")
    else:
        for event in audit_events:
            with st.expander(
                f"{event.verdict} · {display_text(event.timestamp)} · "
                f"{display_text(event.agent_id)} · {display_text(event.action)}"
            ):
                st.write(f"**Request ID:** `{display_text(event.request_id)}`")
                st.write(f"**Category:** {display_text(event.category)}")
                st.write(
                    "**Requested resource (unverified):** "
                    f"`{display_text(event.resource)}`"
                )
                st.write(
                    f"**Risk:** {event.risk_score:.1f}/100 · "
                    f"{display_text(event.risk_level)}"
                )
                st.write(
                    "**Matched policy rules:** "
                    f"{', '.join(map(display_text, event.matched_rule_ids)) or 'None recorded'}"
                )
                st.write("**Decision reasons:**")
                for reason in event.reasons:
                    st.write(f"- {display_text(reason)}")
                st.caption("Sensitive request parameters are not displayed.")

elif section == "Behavioral analytics":
    st.subheader("Historical behavioral analytics")
    analytics_window_label = st.selectbox(
        "Analytics time window",
        tuple(WINDOWS),
        index=2,
        key="analytics_window",
    )
    analytics_duration = WINDOWS[analytics_window_label]
    analytics_start = now - analytics_duration if analytics_duration else None
    analytics_since = as_utc_iso(analytics_start) if analytics_start else None
    try:
        analytics_events = repository.list_security_events(
            limit=MAX_ANALYTICS_EVENTS,
            since_iso=analytics_since,
        )
        matching_event_total = repository.count_security_events(
            since_iso=analytics_since
        )
    except Exception as exc:
        st.error(
            f"Unable to load historical analytics ({type(exc).__name__}).",
            title="Analytics unavailable",
        )
        analytics_events = []
        matching_event_total = 0

    st.caption(
        f"Source: persisted SQLite events · Window: {analytics_window_label} · "
        f"Rows analyzed: {len(analytics_events):,} of {matching_event_total:,}"
    )
    st.info(
        "The database does not identify synthetic versus operational records. "
        "These charts describe stored history only; they are not a live alert feed "
        "or a claim of evaluated machine-learning detection."
    )
    if not analytics_events:
        st.info("No persisted events are available for this time window.")
    else:
        analytics_frame = pd.DataFrame(
            [
                {
                    "Timestamp": pd.to_datetime(event.timestamp, utc=True),
                    "Agent": display_text(event.agent_id),
                    "Action": display_text(event.action),
                    "Decision": event.verdict,
                    "Risk score": event.risk_score,
                    "Policy rules": event.matched_rule_ids,
                }
                for event in analytics_events
            ]
        )
        daily = (
            analytics_frame.assign(
                Day=analytics_frame["Timestamp"].dt.strftime("%Y-%m-%d")
            )
            .groupby(["Day", "Decision"], as_index=False)
            .size()
            .rename(columns={"size": "Events"})
        )
        st.markdown("**Decision volume by day**")
        st.bar_chart(daily, x="Day", y="Events", color="Decision")

        blocked_actions = (
            analytics_frame[analytics_frame["Decision"] == "BLOCK"]
            .groupby("Action", as_index=False)
            .size()
            .rename(columns={"size": "Blocked events"})
            .sort_values("Blocked events", ascending=False)
            .head(10)
        )
        st.markdown("**Repeated blocked actions (loaded sample)**")
        if blocked_actions.empty:
            st.info("No BLOCK decisions appear in the loaded event sample.")
        else:
            st.dataframe(blocked_actions, hide_index=True, width="stretch")

        policy_counts: dict[str, int] = {}
        for rules in analytics_frame["Policy rules"]:
            for rule_id in rules:
                safe_rule_id = display_text(rule_id)
                policy_counts[safe_rule_id] = policy_counts.get(safe_rule_id, 0) + 1
        st.markdown("**Policy-match frequency (loaded sample)**")
        if policy_counts:
            policy_frame = pd.DataFrame(
                [
                    {"Policy rule": rule_id, "Matches": count}
                    for rule_id, count in sorted(
                        policy_counts.items(),
                        key=lambda item: item[1],
                        reverse=True,
                    )[:10]
                ]
            )
            st.bar_chart(policy_frame, x="Policy rule", y="Matches")
        else:
            st.info("No matched policy-rule IDs are available in the loaded sample.")

        if matching_event_total > len(analytics_events):
            st.warning(
                f"Charts use the most recent {MAX_ANALYTICS_EVENTS} rows; "
                f"{matching_event_total - len(analytics_events):,} older matching "
                "events are not represented."
            )

elif section == "Policy simulator":
    st.subheader("Policy simulator")
    st.caption(
        "Policy-only preview. Inputs are untrusted, previews are not persisted, "
        "and no external action or review ticket is created."
    )
    with st.form("simulation_form"):
        left, right = st.columns(2)
        with left:
            sim_agent_id = st.text_input("Agent ID", "agent-simulation")
            sim_action = st.text_input("Action name", "read_faq")
            categories = [category.value for category in ActionCategory]
            sim_category = st.selectbox(
                "Action category",
                categories,
                index=categories.index("READ") if "READ" in categories else 0,
            )
            sim_resource = st.text_input(
                "Requested resource (unverified)",
                "public/demo-resource",
            )
        with right:
            sim_permissions = st.text_input(
                "Claimed permissions (untrusted)",
                help="Client-claimed permissions are not trusted credentials.",
            )
            sim_parameters = st.text_area(
                "Parameters (JSON object)",
                '{\n  "query": "synthetic example"\n}',
                height=120,
            )
        submitted = st.form_submit_button(
            "Evaluate policy preview",
            type="primary",
        )

    if submitted:
        try:
            parsed_parameters = json.loads(sim_parameters) if sim_parameters.strip() else {}
            if not isinstance(parsed_parameters, dict):
                raise ValueError("Parameters must be a JSON object.")
            request = AgentRequest(
                request_id=f"sim-{uuid.uuid4().hex}",
                agent_id=sim_agent_id,
                action=sim_action,
                category=ActionCategory(sim_category),
                resource=sim_resource,
                parameters=parsed_parameters,
                claimed_permissions=[
                    permission.strip()
                    for permission in sim_permissions.split(",")
                    if permission.strip()
                ],
            )
        except (json.JSONDecodeError, ValidationError, ValueError):
            st.error(
                "Enter valid request fields and a JSON object for parameters.",
                title="Invalid simulation input",
            )
        else:
            evaluation = policy_engine.evaluate(
                request=request,
                trusted_permissions=None,
            )
            st.subheader("Policy preview result")
            result_columns = st.columns(3)
            result_columns[0].metric("Policy verdict", evaluation.verdict.value)
            result_columns[1].metric("Risk score", f"{evaluation.risk_score:.1f}/100")
            result_columns[2].metric("Risk level", evaluation.risk_level.value)
            st.write(
                "**Matched policy rules:** "
                f"{', '.join(evaluation.matched_rule_ids) or 'None'}"
            )
            st.write("**Decision reasons:**")
            for reason in evaluation.reasons:
                st.write(f"- {display_text(reason)}")

            if evaluation.verdict == ActionVerdict.ALLOW:
                st.warning(
                    "This is only a policy-engine ALLOW preview. The gateway still "
                    "blocks ALLOW decisions unless a trusted resource classifier "
                    "verifies the target.",
                    title="Not an authorization",
                )
            elif evaluation.verdict == ActionVerdict.REVIEW:
                st.warning(
                    "The preview indicates REVIEW. No ticket was created and no "
                    "review decision was made.",
                    title="Preview only",
                )
            else:
                st.error(
                    "The policy preview returned BLOCK. No action was executed.",
                    title="Action denied by policy",
                )
