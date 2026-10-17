"""Unit tests for Z-AgentShield Decision Gate and execution boundary.

Verifies strict fail-closed gating, protected callback execution counts,
audit failure containment, idempotency protections, and review ticket lifecycle.
"""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock

from zagentshield.audit.logger import AuditLogger, AuditLoggingError
from zagentshield.core.enums import ActionCategory, ActionVerdict, RiskLevel
from zagentshield.core.gate import DecisionGate, GateResult
from zagentshield.core.models import AgentRequest, SecurityEvaluation
from zagentshield.db.database import Database
from zagentshield.db.repository import SecurityRepository
from zagentshield.policies.engine import PolicyEngine


class TestDecisionGate(unittest.TestCase):
    """Test suite for DecisionGate interception and execution boundaries."""

    def setUp(self) -> None:
        """Initialize temporary database, repository, audit logger, policy engine, and gate."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_gate.db"
        self.db = Database(db_path=self.db_path)
        self.db.init_db()

        self.repository = SecurityRepository(self.db)
        self.audit_logger = AuditLogger(self.repository)
        self.policy_engine = PolicyEngine.from_yaml_file("config/policies.yaml")
        self.gate = DecisionGate(
            policy_engine=self.policy_engine,
            audit_logger=self.audit_logger,
            repository=self.repository,
        )

    def tearDown(self) -> None:
        """Clean up temporary test directory."""
        self.temp_dir.cleanup()

    def test_allow_invokes_callback_exactly_once(self) -> None:
        """Verify ALLOW verdict invokes the protected callback exactly once."""
        request = AgentRequest(
            request_id="req-allow-op",
            agent_id="agent-catalog",
            action="query_catalog_items",
            category=ActionCategory.READ,
            resource="api://catalog/items/1",
        )
        mock_callback = MagicMock(return_value={"status": "data_retrieved"})

        result = self.gate.intercept_and_execute(
            request=request,
            operation=mock_callback,
            trusted_permissions={"catalog.read"},
        )

        self.assertTrue(result.allowed)
        self.assertEqual(result.verdict, ActionVerdict.ALLOW)
        self.assertEqual(result.execution_result, {"status": "data_retrieved"})
        mock_callback.assert_called_once()

    def test_review_never_invokes_callback(self) -> None:
        """Verify REVIEW verdict denies execution and callback is NEVER invoked."""
        request = AgentRequest(
            request_id="req-review-op",
            agent_id="agent-analyst",
            action="export_customer_data",
            category=ActionCategory.EXPORT,
            resource="s3://exports/clients.csv",
            parameters={"limit": 1000},
            claimed_permissions=["export.data"],
        )
        mock_callback = MagicMock()

        result = self.gate.intercept_and_execute(
            request=request,
            operation=mock_callback,
            trusted_permissions={"export.data"},
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.verdict, ActionVerdict.REVIEW)
        self.assertIsNotNone(result.ticket_id)
        mock_callback.assert_not_called()

    def test_block_never_invokes_callback(self) -> None:
        """Verify BLOCK verdict denies execution and callback is NEVER invoked."""
        request = AgentRequest(
            request_id="req-block-op",
            agent_id="agent-dev",
            action="drop_table_users",
            category=ActionCategory.ADMIN,
            resource="db://finance/users",
        )
        mock_callback = MagicMock()

        result = self.gate.intercept_and_execute(
            request=request,
            operation=mock_callback,
            trusted_permissions={"admin.all"},
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.verdict, ActionVerdict.BLOCK)
        mock_callback.assert_not_called()

    def test_missing_evaluation_evaluates_and_fails_closed_safely(self) -> None:
        """Verify when no evaluation is provided, policy engine evaluates; if blocked, callback never runs."""
        request = AgentRequest(
            request_id="req-secrets-op",
            agent_id="agent-bad",
            action="read_key",
            category=ActionCategory.READ,
            resource="secrets://master/token",
        )
        mock_callback = MagicMock()

        result = self.gate.intercept_and_execute(
            request=request,
            operation=mock_callback,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.verdict, ActionVerdict.BLOCK)
        mock_callback.assert_not_called()

    def test_invalid_or_mismatched_evaluation_fails_closed(self) -> None:
        """Verify mismatched request_id in evaluation triggers fail-closed BLOCK."""
        request = AgentRequest(
            request_id="req-legit-01",
            agent_id="agent-01",
            action="query_catalog_items",
            category=ActionCategory.READ,
            resource="api://catalog/items/1",
        )
        # Evaluation with different request_id
        mismatched_eval = SecurityEvaluation(
            request_id="req-DIFFERENT-ID",
            verdict=ActionVerdict.ALLOW,
            risk_score=10.0,
            risk_level=RiskLevel.LOW,
            reasons=["Mismatched spoof"],
        )
        mock_callback = MagicMock()

        result = self.gate.intercept_and_execute(
            request=request,
            operation=mock_callback,
            evaluation=mismatched_eval,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.verdict, ActionVerdict.BLOCK)
        self.assertIn("mismatched", result.error.lower())
        mock_callback.assert_not_called()

    def test_policy_engine_exception_fails_closed(self) -> None:
        """Verify policy engine exceptions fail closed without executing the callback."""
        mock_engine = MagicMock()
        mock_engine.evaluate.side_effect = RuntimeError("Policy rule evaluation failure")

        faulty_gate = DecisionGate(
            policy_engine=mock_engine,
            audit_logger=self.audit_logger,
            repository=self.repository,
        )
        request = AgentRequest(
            request_id="req-engine-fault",
            agent_id="agent-01",
            action="query_catalog_items",
            category=ActionCategory.READ,
            resource="api://catalog/items/1",
        )
        mock_callback = MagicMock()

        result = faulty_gate.intercept_and_execute(
            request=request,
            operation=mock_callback,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.verdict, ActionVerdict.BLOCK)
        self.assertIn("policy engine error", result.error.lower())
        mock_callback.assert_not_called()

    def test_authorization_failure_never_invokes_callback(self) -> None:
        """Verify that lack of trusted authorization blocks action without running callback."""
        request = AgentRequest(
            request_id="req-no-auth",
            agent_id="agent-guest",
            action="query_report",
            category=ActionCategory.READ,
            resource="db://reporting/metrics",
        )
        mock_callback = MagicMock()

        result = self.gate.intercept_and_execute(
            request=request,
            operation=mock_callback,
            trusted_permissions=set(),  # Missing required reports.read
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.verdict, ActionVerdict.BLOCK)
        mock_callback.assert_not_called()

    def test_agent_supplied_permission_claims_cannot_override_server_auth(self) -> None:
        """Verify agent claimed_permissions are ignored by gate and cannot bypass server authorization."""
        request = AgentRequest(
            request_id="req-claim-bypass",
            agent_id="agent-untrusted",
            action="query_report",
            category=ActionCategory.READ,
            resource="db://reporting/metrics",
            claimed_permissions=["reports.read", "admin.super"],
        )
        mock_callback = MagicMock()

        # Server trusted permissions are empty
        result = self.gate.intercept_and_execute(
            request=request,
            operation=mock_callback,
            trusted_permissions=set(),
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.verdict, ActionVerdict.BLOCK)
        mock_callback.assert_not_called()

    def test_pending_review_returns_ticket_id(self) -> None:
        """Verify pending review requests return the correct ticket ID from the database."""
        request = AgentRequest(
            request_id="req-ticket-check",
            agent_id="agent-analyst",
            action="export_customer_data",
            category=ActionCategory.EXPORT,
            resource="s3://exports/data.csv",
        )
        mock_callback = MagicMock()

        result = self.gate.intercept_and_execute(
            request=request,
            operation=mock_callback,
            trusted_permissions={"export.data"},
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.verdict, ActionVerdict.REVIEW)
        self.assertIsNotNone(result.ticket_id)
        self.assertTrue(result.ticket_id.startswith("tkt-"))

        # Verify ticket in database
        ticket = self.repository.get_review_ticket(result.ticket_id)
        self.assertIsNotNone(ticket)
        self.assertEqual(ticket.status, "PENDING")
        mock_callback.assert_not_called()

    def test_audit_failure_never_invokes_callback(self) -> None:
        """Verify audit persistence failure prevents callback execution (fails closed)."""
        mock_audit_logger = MagicMock()
        mock_audit_logger.log_evaluation.side_effect = AuditLoggingError("Database disk full")

        faulty_gate = DecisionGate(
            policy_engine=self.policy_engine,
            audit_logger=mock_audit_logger,
            repository=self.repository,
        )
        request = AgentRequest(
            request_id="req-audit-fail",
            agent_id="agent-catalog",
            action="query_catalog_items",
            category=ActionCategory.READ,
            resource="api://catalog/items/1",
        )
        mock_callback = MagicMock()

        result = faulty_gate.intercept_and_execute(
            request=request,
            operation=mock_callback,
            trusted_permissions={"catalog.read"},
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.verdict, ActionVerdict.BLOCK)
        self.assertIn("audit logging failed", result.error.lower())
        mock_callback.assert_not_called()

    def test_callback_exception_handled_cleanly_verdict_unchanged(self) -> None:
        """Verify exception raised inside protected callback is handled safely without crashing gate."""
        request = AgentRequest(
            request_id="req-callback-crash",
            agent_id="agent-catalog",
            action="query_catalog_items",
            category=ActionCategory.READ,
            resource="api://catalog/items/1",
        )

        def crashing_callback():
            raise ConnectionResetError("Remote API gateway timeout")

        result = self.gate.intercept_and_execute(
            request=request,
            operation=crashing_callback,
            trusted_permissions={"catalog.read"},
        )

        self.assertTrue(result.allowed)
        self.assertEqual(result.verdict, ActionVerdict.ALLOW)
        self.assertIn("Remote API gateway timeout", result.error)
        self.assertIsNone(result.execution_result)

    def test_duplicate_request_idempotency_prevents_repeated_execution(self) -> None:
        """Verify that duplicate request_ids are blocked from repeated execution."""
        request = AgentRequest(
            request_id="req-idempotent-01",
            agent_id="agent-catalog",
            action="query_catalog_items",
            category=ActionCategory.READ,
            resource="api://catalog/items/1",
        )
        mock_callback = MagicMock(return_value="executed_first_time")

        # First execution -> ALLOWed, callback runs
        result1 = self.gate.intercept_and_execute(
            request=request,
            operation=mock_callback,
            trusted_permissions={"catalog.read"},
        )
        self.assertTrue(result1.allowed)
        self.assertEqual(mock_callback.call_count, 1)

        # Second execution with exact same request_id -> BLOCKED by idempotency guard
        result2 = self.gate.intercept_and_execute(
            request=request,
            operation=mock_callback,
            trusted_permissions={"catalog.read"},
        )
        self.assertFalse(result2.allowed)
        self.assertIn("Duplicate request_id", result2.error)
        # Total callback call count must STILL be 1 (never re-executed)
        self.assertEqual(mock_callback.call_count, 1)

    def test_execute_approved_ticket_lifecycle(self) -> None:
        """Verify execution of a review ticket requires explicit human approval."""
        # 1. Create a reviewable request
        request = AgentRequest(
            request_id="req-approval-flow",
            agent_id="agent-analyst",
            action="export_customer_data",
            category=ActionCategory.EXPORT,
            resource="s3://exports/data.csv",
        )
        mock_callback = MagicMock(return_value="export_completed")

        result = self.gate.intercept_and_execute(
            request=request,
            operation=mock_callback,
            trusted_permissions={"export.data"},
        )
        self.assertFalse(result.allowed)
        mock_callback.assert_not_called()
        ticket_id = result.ticket_id
        self.assertIsNotNone(ticket_id)

        # 2. Attempt to execute while ticket is still PENDING -> Must be rejected
        pending_attempt = self.gate.execute_approved_ticket(
            ticket_id=ticket_id,
            operation=mock_callback,
            reviewer_id="attacker",
        )
        self.assertFalse(pending_attempt.allowed)
        mock_callback.assert_not_called()

        # 3. Approve ticket explicitly via repository
        self.repository.update_review_status(
            ticket_id=ticket_id,
            new_status="APPROVED",
            reviewer_id="secops_lead",
            reviewer_notes="Approved after human verification.",
        )

        # 4. Execute approved ticket -> Must succeed and run callback exactly once
        approved_result = self.gate.execute_approved_ticket(
            ticket_id=ticket_id,
            operation=mock_callback,
            reviewer_id="secops_lead",
        )
        self.assertTrue(approved_result.allowed)
        self.assertEqual(approved_result.execution_result, "export_completed")
        mock_callback.assert_called_once()


if __name__ == "__main__":
    unittest.main()
