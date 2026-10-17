"""Seed realistic demonstration telemetry for Z-AgentShield.

Populates the SQLite database with synthetic enterprise AI agent events:
- Routine reads (ALLOW)
- High-value financial exports and updates (REVIEW)
- Unauthorized secret exfiltration and shell execution attempts (BLOCK)
- Pending and decided human-review tickets
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import uuid

# Ensure 'src' is importable
ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from zagentshield.audit.logger import AuditLogger
from zagentshield.config import get_settings
from zagentshield.core.enums import ActionCategory, ActionVerdict, RiskLevel
from zagentshield.core.models import AgentRequest, SecurityEvaluation
from zagentshield.db.database import Database
from zagentshield.db.repository import SecurityRepository


def seed():
    settings = get_settings()
    db = Database(settings.database_path)
    db.init_db()
    repo = SecurityRepository(db)
    audit = AuditLogger(repo)

    now = datetime.now(timezone.utc)

    sample_scenarios = [
        # ALLOW Scenarios
        {
            "agent_id": "agent-customer-support-01",
            "action": "read_faq",
            "category": ActionCategory.READ,
            "resource": "public/faq/knowledge_base",
            "verdict": ActionVerdict.ALLOW,
            "risk_score": 5.0,
            "risk_level": RiskLevel.LOW,
            "reasons": ["Action permitted under public read policy."],
            "rules": ["allow-read-public"],
            "params": {"query": "how to reset password"},
            "minutes_ago": 45,
        },
        {
            "agent_id": "agent-analytics-bot-04",
            "action": "query_metrics",
            "category": ActionCategory.READ,
            "resource": "internal/metrics/daily_summary",
            "verdict": ActionVerdict.ALLOW,
            "risk_score": 15.0,
            "risk_level": RiskLevel.LOW,
            "reasons": ["Action permitted under internal analytics read policy."],
            "rules": ["allow-internal-metrics"],
            "params": {"date": "2026-10-16", "metric": "active_users"},
            "minutes_ago": 30,
        },
        # REVIEW Scenarios
        {
            "agent_id": "agent-finance-processor-02",
            "action": "export_customer_data",
            "category": ActionCategory.EXPORT,
            "resource": "db://customers/financial_records",
            "verdict": ActionVerdict.REVIEW,
            "risk_score": 65.0,
            "risk_level": RiskLevel.HIGH,
            "reasons": ["Bulk customer financial export requires human authorization."],
            "rules": ["REV-BULK-DATA-EXPORT"],
            "params": {"records": 25000, "destination": "s3://exports/q3.csv", "api_key": "sk-prod-998877"},
            "minutes_ago": 20,
            "needs_ticket": True,
            "ticket_status": "PENDING",
        },
        {
            "agent_id": "agent-hr-assistant-03",
            "action": "update_salary_band",
            "category": ActionCategory.UPDATE,
            "resource": "db://hr/salary_bands",
            "verdict": ActionVerdict.REVIEW,
            "risk_score": 58.0,
            "risk_level": RiskLevel.HIGH,
            "reasons": ["Modification to compensation tables requires manager review."],
            "rules": ["REV-PRIVILEGED-UPDATE"],
            "params": {"department": "Engineering", "band": "L5"},
            "minutes_ago": 15,
            "needs_ticket": True,
            "ticket_status": "APPROVED",
            "reviewer_id": "sec-lead-alice",
            "reviewer_notes": "Verified annual compensation adjustments with HR VP.",
        },
        # BLOCK Scenarios
        {
            "agent_id": "agent-compromised-bot-99",
            "action": "get_secret_vault",
            "category": ActionCategory.READ,
            "resource": "secrets://vault/production/master_key",
            "verdict": ActionVerdict.BLOCK,
            "risk_score": 100.0,
            "risk_level": RiskLevel.CRITICAL,
            "reasons": ["Direct access to secrets vault is strictly prohibited."],
            "rules": ["DENY-RAW-SECRETS"],
            "params": {"auth_token": "bearer eyJhbGciOi..."},
            "minutes_ago": 10,
        },
        {
            "agent_id": "agent-rogue-tool-07",
            "action": "exec_shell",
            "category": ActionCategory.ADMIN,
            "resource": "system://shell/bash",
            "verdict": ActionVerdict.BLOCK,
            "risk_score": 100.0,
            "risk_level": RiskLevel.CRITICAL,
            "reasons": ["Arbitrary shell execution strictly prohibited by kernel boundary."],
            "rules": ["DENY-UNAUTHORIZED-OS-EXEC"],
            "params": {"cmd": "rm -rf /var/data"},
            "minutes_ago": 5,
        },
    ]

    print(f"Seeding demo data into {settings.database_path}...")
    for s in sample_scenarios:
        req_id = f"req-seed-{uuid.uuid4().hex[:8]}"
        timestamp = now - timedelta(minutes=s["minutes_ago"])

        req = AgentRequest(
            request_id=req_id,
            agent_id=s["agent_id"],
            action=s["action"],
            category=s["category"],
            resource=s["resource"],
            parameters=s["params"],
            timestamp=timestamp,
        )

        evaluation = SecurityEvaluation(
            request_id=req_id,
            verdict=s["verdict"],
            risk_score=s["risk_score"],
            risk_level=s["risk_level"],
            reasons=s["reasons"],
            matched_rule_ids=s["rules"],
            timestamp=timestamp,
        )

        audit.log_evaluation(req, evaluation)

        if s.get("needs_ticket") and s.get("ticket_status") != "PENDING":
            ticket = repo.get_review_ticket_by_request_id(req_id)
            if ticket:
                repo.update_review_status(
                    ticket_id=ticket.ticket_id,
                    new_status=s["ticket_status"],
                    reviewer_id=s.get("reviewer_id", "admin"),
                    reviewer_notes=s.get("reviewer_notes", "Approved during routine audit."),
                )

    print("Seeding complete. Run 'streamlit run dashboard/app.py' to explore the SOC Operations Console.")


if __name__ == "__main__":
    seed()
