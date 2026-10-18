"""Unit tests for Z-AgentShield SQLite Database and Repository layer.

Tests schema creation, parameterized SQL safety, audit trail storage,
idempotency, and review queue status transitions.
"""

from pathlib import Path
import tempfile
import unittest

from zagentshield.core.enums import ActionCategory, ActionVerdict, RiskLevel
from zagentshield.db.database import Database
from zagentshield.db.repository import (
    InvalidReviewStateError,
    SecurityRepository,
)


class TestDatabaseRepository(unittest.TestCase):
    """Test suite for SQLite Database and SecurityRepository."""

    def setUp(self) -> None:
        """Create a fresh temporary SQLite database for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_zagentshield.db"
        self.db = Database(db_path=self.db_path)
        self.db.init_db()
        self.repo = SecurityRepository(self.db)

    def tearDown(self) -> None:
        """Clean up temporary database files."""
        self.temp_dir.cleanup()

    def test_schema_initialization(self) -> None:
        """Verify tables and indexes are created properly upon init_db."""
        with self.db.connection() as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table';"
            ).fetchall()
            table_names = {row["name"] for row in tables}
            self.assertIn("security_events", table_names)
            self.assertIn("review_queue", table_names)

            indices = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index';"
            ).fetchall()
            index_names = {row["name"] for row in indices}
            self.assertIn("idx_security_events_request_id", index_names)
            self.assertIn("idx_review_queue_status", index_names)

    def test_persist_security_events_allow_review_block(self) -> None:
        """Verify persisting ALLOW, REVIEW, and BLOCK decisions and retrieving them."""
        verdicts = [
            ("req-allow-1", ActionVerdict.ALLOW.value, 15.0, RiskLevel.LOW.value),
            ("req-review-1", ActionVerdict.REVIEW.value, 60.0, RiskLevel.HIGH.value),
            ("req-block-1", ActionVerdict.BLOCK.value, 95.0, RiskLevel.CRITICAL.value),
        ]
        for req_id, verdict, score, level in verdicts:
            inserted = self.repo.record_security_event(
                request_id=req_id,
                agent_id="agent-test",
                action="test_action",
                category=ActionCategory.READ.value,
                resource="db://test",
                verdict=verdict,
                risk_score=score,
                risk_level=level,
                reasons=[f"Test reason for {verdict}"],
                matched_rule_ids=["RULE-TEST"],
                parameters_redacted={"key": "val"},
            )
            self.assertTrue(inserted)

            # Retrieve and verify
            record = self.repo.get_security_event(req_id)
            self.assertIsNotNone(record)
            self.assertEqual(record.request_id, req_id)
            self.assertEqual(record.verdict, verdict)
            self.assertEqual(record.risk_score, score)
            self.assertEqual(record.risk_level, level)

    def test_listing_audit_events_with_filter(self) -> None:
        """Verify listing events with pagination and filtering by verdict."""
        for i in range(10):
            v = ActionVerdict.ALLOW.value if i % 2 == 0 else ActionVerdict.BLOCK.value
            self.repo.record_security_event(
                request_id=f"req-batch-{i}",
                agent_id="agent-01",
                action="query",
                category=ActionCategory.READ.value,
                resource="db://test",
                verdict=v,
                risk_score=20.0,
                risk_level=RiskLevel.LOW.value,
                reasons=["Batch item"],
                matched_rule_ids=[],
            )

        all_events = self.repo.list_security_events(limit=50)
        self.assertEqual(len(all_events), 10)

        allow_events = self.repo.list_security_events(limit=50, verdict=ActionVerdict.ALLOW.value)
        self.assertEqual(len(allow_events), 5)
        for ev in allow_events:
            self.assertEqual(ev.verdict, ActionVerdict.ALLOW.value)

    def test_summary_and_filtered_event_pagination(self) -> None:
        for request_id, verdict, agent_id, timestamp in [
            ("req-summary-1", "ALLOW", "agent-a", "2026-01-01T00:00:00+00:00"),
            ("req-summary-2", "BLOCK", "agent-b", "2026-01-02T00:00:00+00:00"),
            ("req-summary-3", "BLOCK", "agent-a", "2026-01-03T00:00:00+00:00"),
        ]:
            self.repo.record_security_event(
                request_id=request_id,
                agent_id=agent_id,
                action="read",
                category="READ",
                resource="public/demo",
                verdict=verdict,
                risk_score=20.0,
                risk_level="LOW",
                reasons=[],
                matched_rule_ids=[],
                timestamp=timestamp,
            )

        summary = self.repo.get_event_summary("2026-01-02T00:00:00+00:00")
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["block"], 2)
        self.assertEqual(summary["latest_event_at"], "2026-01-03T00:00:00+00:00")
        self.assertEqual(
            self.repo.count_security_events(
                verdict="BLOCK",
                agent_id="agent-a",
                since_iso="2026-01-01T00:00:00+00:00",
            ),
            1,
        )
        page = self.repo.list_security_events(
            limit=1,
            offset=1,
            verdict="BLOCK",
            since_iso="2026-01-02T00:00:00+00:00",
        )
        self.assertEqual(len(page), 1)
        self.assertEqual(page[0].request_id, "req-summary-2")

    def test_duplicate_event_handling_idempotent(self) -> None:
        """Verify that duplicate request_id does not cause an unhandled exception or duplicate entry."""
        first_insert = self.repo.record_security_event(
            request_id="req-unique-id",
            agent_id="agent-01",
            action="read",
            category=ActionCategory.READ.value,
            resource="db://data",
            verdict=ActionVerdict.ALLOW.value,
            risk_score=10.0,
            risk_level=RiskLevel.LOW.value,
            reasons=["First insert"],
            matched_rule_ids=[],
        )
        self.assertTrue(first_insert)

        # Attempt duplicate insert
        second_insert = self.repo.record_security_event(
            request_id="req-unique-id",
            agent_id="agent-01",
            action="read",
            category=ActionCategory.READ.value,
            resource="db://data",
            verdict=ActionVerdict.BLOCK.value,
            risk_score=90.0,
            risk_level=RiskLevel.CRITICAL.value,
            reasons=["Duplicate insert attempt"],
            matched_rule_ids=[],
        )
        self.assertFalse(second_insert)

        # Confirm original record remained unchanged
        record = self.repo.get_security_event("req-unique-id")
        self.assertIsNotNone(record)
        self.assertEqual(record.verdict, ActionVerdict.ALLOW.value)

    def test_sql_parameterization_against_injection(self) -> None:
        """Verify parameterized queries handle SQL injection syntax without altering database state."""
        malicious_id = "req-1'; DROP TABLE security_events; --"
        malicious_agent = "agent-1' OR '1'='1"

        inserted = self.repo.record_security_event(
            request_id=malicious_id,
            agent_id=malicious_agent,
            action="test_action",
            category=ActionCategory.READ.value,
            resource="db://test",
            verdict=ActionVerdict.BLOCK.value,
            risk_score=99.0,
            risk_level=RiskLevel.CRITICAL.value,
            reasons=["Injection payload safely quoted"],
            matched_rule_ids=[],
        )
        self.assertTrue(inserted)

        # Confirm table still exists and data was inserted literally
        record = self.repo.get_security_event(malicious_id)
        self.assertIsNotNone(record)
        self.assertEqual(record.request_id, malicious_id)
        self.assertEqual(record.agent_id, malicious_agent)

    def test_review_queue_creation_and_retrieval(self) -> None:
        """Verify review ticket creation, querying by ID, and listing pending tickets."""
        ticket = self.repo.create_review_ticket(
            request_id="req-rev-ticket-01",
            agent_id="agent-analyst",
            action="export_report",
            category=ActionCategory.EXPORT.value,
            resource="s3://reports",
            risk_score=65.0,
            risk_level=RiskLevel.HIGH.value,
            reasons=["Bulk export triggers review"],
        )
        self.assertEqual(ticket.status, "PENDING")
        self.assertTrue(ticket.ticket_id.startswith("tkt-"))

        # Retrieve by ticket_id
        fetched = self.repo.get_review_ticket(ticket.ticket_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.ticket_id, ticket.ticket_id)
        self.assertEqual(fetched.status, "PENDING")

        # Retrieve by request_id
        by_req = self.repo.get_review_ticket_by_request_id("req-rev-ticket-01")
        self.assertIsNotNone(by_req)
        self.assertEqual(by_req.ticket_id, ticket.ticket_id)

        # List pending
        pending_list = self.repo.list_pending_reviews()
        self.assertEqual(len(pending_list), 1)
        self.assertEqual(self.repo.count_pending_reviews(), 1)

    def test_pending_review_filters_and_pagination(self) -> None:
        for index, agent_id, risk in [
            (1, "agent-alpha", "HIGH"),
            (2, "agent-beta", "CRITICAL"),
            (3, "agent-alpha", "HIGH"),
        ]:
            self.repo.create_review_ticket(
                request_id=f"req-review-page-{index}",
                agent_id=agent_id,
                action="export",
                category="EXPORT",
                resource="data/demo",
                risk_score=70.0,
                risk_level=risk,
                reasons=["Needs review"],
            )

        self.assertEqual(
            self.repo.count_pending_reviews(agent_id="alpha", risk_level="HIGH"),
            2,
        )
        page = self.repo.list_pending_reviews(
            limit=1,
            offset=1,
            agent_id="alpha",
            risk_level="HIGH",
        )
        self.assertEqual(len(page), 1)
        self.assertEqual(page[0].agent_id, "agent-alpha")

    def test_valid_review_status_transitions(self) -> None:
        """Verify valid transitions from PENDING to APPROVED and PENDING to REJECTED."""
        # 1. PENDING -> APPROVED
        t1 = self.repo.create_review_ticket(
            request_id="req-t1",
            agent_id="agent-01",
            action="export",
            category="EXPORT",
            resource="s3://data",
            risk_score=60.0,
            risk_level="HIGH",
            reasons=["Review needed"],
        )
        approved = self.repo.update_review_status(
            t1.ticket_id, "APPROVED", reviewer_id="secops_admin", reviewer_notes="Approved for export"
        )
        self.assertTrue(approved)
        updated_t1 = self.repo.get_review_ticket(t1.ticket_id)
        self.assertEqual(updated_t1.status, "APPROVED")
        self.assertEqual(updated_t1.reviewer_id, "secops_admin")
        self.assertEqual(updated_t1.reviewer_notes, "Approved for export")

        # 2. PENDING -> REJECTED
        t2 = self.repo.create_review_ticket(
            request_id="req-t2",
            agent_id="agent-02",
            action="export",
            category="EXPORT",
            resource="s3://data",
            risk_score=60.0,
            risk_level="HIGH",
            reasons=["Review needed"],
        )
        rejected = self.repo.update_review_status(
            t2.ticket_id, "REJECTED", reviewer_id="secops_admin", reviewer_notes="Denied by security"
        )
        self.assertTrue(rejected)
        updated_t2 = self.repo.get_review_ticket(t2.ticket_id)
        self.assertEqual(updated_t2.status, "REJECTED")

    def test_invalid_review_status_transitions_rejected(self) -> None:
        """Verify that transitions from terminal states or to invalid states are rejected."""
        ticket = self.repo.create_review_ticket(
            request_id="req-terminal-test",
            agent_id="agent-01",
            action="export",
            category="EXPORT",
            resource="s3://data",
            risk_score=60.0,
            risk_level="HIGH",
            reasons=["Review needed"],
        )
        # Transition to APPROVED (terminal)
        self.repo.update_review_status(ticket.ticket_id, "APPROVED", reviewer_id="admin_1")

        # Attempt to change from APPROVED to REJECTED (illegal)
        with self.assertRaises(InvalidReviewStateError):
            self.repo.update_review_status(ticket.ticket_id, "REJECTED", reviewer_id="admin_2")

        # Attempt unknown status
        with self.assertRaises(InvalidReviewStateError):
            self.repo.update_review_status(ticket.ticket_id, "IN_PROGRESS", reviewer_id="admin_2")

    def test_hash_chain_verifies_and_detects_tampering(self) -> None:
        self.repo.record_security_event(
            request_id="req-chain-01",
            agent_id="agent-test",
            action="read",
            category="READ",
            resource="synthetic/public",
            verdict="BLOCK",
            risk_score=99.0,
            risk_level="CRITICAL",
            reasons=["Synthetic integrity test"],
            matched_rule_ids=["test-rule"],
        )
        ticket = self.repo.create_review_ticket(
            request_id="req-chain-review",
            agent_id="agent-test",
            action="export",
            category="EXPORT",
            resource="synthetic/data",
            risk_score=60.0,
            risk_level="HIGH",
            reasons=["Synthetic review integrity test"],
        )
        self.repo.update_review_status(
            ticket.ticket_id, "REJECTED", reviewer_id="analyst-test"
        )

        verification = self.repo.verify_audit_chain()
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["entries_checked"], 2)

        with self.db.connection() as conn:
            conn.execute(
                "UPDATE audit_integrity_chain SET payload_json = ? WHERE sequence = 1;",
                ('{"tampered":true}',),
            )
        verification = self.repo.verify_audit_chain()
        self.assertFalse(verification["valid"])
        self.assertEqual(verification["failure_sequence"], 1)


if __name__ == "__main__":
    unittest.main()
