"""Unit tests for Z-AgentShield Audit Logging and Sensitive-Data Redaction.

Tests redaction of credentials, API keys, private keys, JWTs, nested dictionaries,
immutability of input objects, and secure persistence through AuditLogger.
"""

from pathlib import Path
import tempfile
import unittest

from zagentshield.audit.logger import AuditLogger, AuditLoggingError
from zagentshield.audit.redaction import (
    REDACTED_CARD_PLACEHOLDER,
    REDACTED_JWT_PLACEHOLDER,
    REDACTED_KEY_PLACEHOLDER,
    REDACTED_PLACEHOLDER,
    is_sensitive_key,
    redact_sensitive_data,
    redact_string,
)
from zagentshield.core.enums import ActionCategory, ActionVerdict, RiskLevel
from zagentshield.core.models import AgentRequest, SecurityEvaluation
from zagentshield.db.database import Database
from zagentshield.db.repository import SecurityRepository


class TestRedactionModule(unittest.TestCase):
    """Test suite for sensitive data redaction patterns and recursion."""

    def test_key_name_detection(self) -> None:
        """Verify detection of sensitive dictionary keys."""
        sensitive_keys = [
            "password",
            "db_password",
            "api_key",
            "client_secret",
            "access_token",
            "refresh_token",
            "private_key",
            "authorization",
            "cvv",
        ]
        for key in sensitive_keys:
            with self.subTest(key=key):
                self.assertTrue(is_sensitive_key(key))

        non_sensitive = ["username", "user_id", "email", "query", "limit", "resource_id"]
        for key in non_sensitive:
            with self.subTest(key=key):
                self.assertFalse(is_sensitive_key(key))

    def test_redact_sensitive_dictionary_keys(self) -> None:
        """Verify sensitive dictionary keys are masked while normal keys remain."""
        data = {
            "account_id": "acc-12345",
            "api_key": "secret_live_key_abcdef123456",
            "password": "SuperSecretPassword!",
            "details": {
                "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ...\n-----END RSA PRIVATE KEY-----",
                "client_secret": "my-client-secret-999",
                "user_name": "analyst_alice",
            },
        }
        sanitized = redact_sensitive_data(data)

        self.assertEqual(sanitized["account_id"], "acc-12345")
        self.assertEqual(sanitized["api_key"], REDACTED_PLACEHOLDER)
        self.assertEqual(sanitized["password"], REDACTED_PLACEHOLDER)
        self.assertEqual(sanitized["details"]["private_key"], REDACTED_PLACEHOLDER)
        self.assertEqual(sanitized["details"]["client_secret"], REDACTED_PLACEHOLDER)
        self.assertEqual(sanitized["details"]["user_name"], "analyst_alice")

    def test_redact_bearer_token_string(self) -> None:
        """Verify inline Bearer tokens in headers or strings are masked."""
        raw_header = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMC6Y5bP3iUrWMQg52vdnxPuqAOM"
        redacted = redact_string(raw_header)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", redacted)
        self.assertIn("Bearer [REDACTED]", redacted)

    def test_redact_pem_private_keys(self) -> None:
        """Verify PEM formatted private keys in raw strings are masked."""
        pem_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y1mZ...fakekeycontent...7xQIDAQAB\n"
            "-----END RSA PRIVATE KEY-----"
        )
        sample_log = f"Loaded private key:\n{pem_key}\nReady to sign."
        redacted = redact_string(sample_log)
        self.assertNotIn("fakekeycontent", redacted)
        self.assertIn(REDACTED_KEY_PLACEHOLDER, redacted)

    def test_redact_credit_cards(self) -> None:
        """Verify 16-digit credit card numbers are masked."""
        raw_text = "Processing transaction for card 4111-2222-3333-4444 now."
        redacted = redact_string(raw_text)
        self.assertNotIn("4111-2222-3333-4444", redacted)
        self.assertIn(REDACTED_CARD_PLACEHOLDER, redacted)

    def test_input_immutability(self) -> None:
        """Verify that caller's original dictionary is NOT mutated by redaction."""
        original = {
            "token": "secret_token_12345",
            "nested": {"password": "admin_password"},
        }
        original_copy = {
            "token": "secret_token_12345",
            "nested": {"password": "admin_password"},
        }

        sanitized = redact_sensitive_data(original)
        self.assertEqual(original, original_copy)
        self.assertEqual(original["token"], "secret_token_12345")
        self.assertEqual(original["nested"]["password"], "admin_password")
        self.assertEqual(sanitized["token"], REDACTED_PLACEHOLDER)


class TestAuditLogger(unittest.TestCase):
    """Test suite for AuditLogger integration with SQLite."""

    def setUp(self) -> None:
        """Initialize temporary database and AuditLogger."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_audit.db"
        self.db = Database(db_path=self.db_path)
        self.db.init_db()
        self.repo = SecurityRepository(self.db)
        self.logger = AuditLogger(self.repo)

    def tearDown(self) -> None:
        """Clean up temporary files."""
        self.temp_dir.cleanup()

    def test_log_allow_evaluation_persists_redacted_parameters(self) -> None:
        """Verify that logging an ALLOW evaluation redacts sensitive parameters."""
        req = AgentRequest(
            request_id="req-allow-audit",
            agent_id="agent-01",
            action="read_account",
            category=ActionCategory.READ,
            resource="db://finance/accounts/1",
            parameters={
                "account_id": "1",
                "api_key": "raw_sensitive_key_999",
                "auth_header": "Bearer token1234567890",
            },
        )
        eval_result = SecurityEvaluation(
            request_id="req-allow-audit",
            verdict=ActionVerdict.ALLOW,
            risk_score=15.0,
            risk_level=RiskLevel.LOW,
            reasons=["Routine read authorized."],
            matched_rule_ids=["ALLOW-CATALOG-READ"],
        )

        logged = self.logger.log_evaluation(req, eval_result)
        self.assertTrue(logged)

        # Inspect persisted event
        event = self.repo.get_security_event("req-allow-audit")
        self.assertIsNotNone(event)
        self.assertEqual(event.verdict, ActionVerdict.ALLOW.value)
        self.assertEqual(event.parameters_redacted["account_id"], "1")
        self.assertEqual(event.parameters_redacted["api_key"], REDACTED_PLACEHOLDER)
        self.assertNotIn("raw_sensitive_key_999", str(event.parameters_redacted))

    def test_log_review_evaluation_creates_review_ticket(self) -> None:
        """Verify that logging a REVIEW evaluation creates a corresponding ticket in review_queue."""
        req = AgentRequest(
            request_id="req-review-audit",
            agent_id="agent-export",
            action="export_data",
            category=ActionCategory.EXPORT,
            resource="s3://exports/data.csv",
            parameters={"limit": 10000},
        )
        eval_result = SecurityEvaluation(
            request_id="req-review-audit",
            verdict=ActionVerdict.REVIEW,
            risk_score=65.0,
            risk_level=RiskLevel.HIGH,
            reasons=["Bulk export triggers review."],
            matched_rule_ids=["REV-BULK-DATA-EXPORT"],
        )

        logged = self.logger.log_evaluation(req, eval_result)
        self.assertTrue(logged)

        # Verify audit event exists
        event = self.repo.get_security_event("req-review-audit")
        self.assertIsNotNone(event)
        self.assertEqual(event.verdict, ActionVerdict.REVIEW.value)

        # Verify review ticket exists in PENDING status
        ticket = self.repo.get_review_ticket_by_request_id("req-review-audit")
        self.assertIsNotNone(ticket)
        self.assertEqual(ticket.status, "PENDING")
        self.assertEqual(ticket.request_id, "req-review-audit")

    def test_log_block_evaluation_persisted(self) -> None:
        """Verify BLOCK decisions are properly audited."""
        req = AgentRequest(
            request_id="req-block-audit",
            agent_id="agent-bad",
            action="drop_table",
            category=ActionCategory.ADMIN,
            resource="db://prod/users",
        )
        eval_result = SecurityEvaluation(
            request_id="req-block-audit",
            verdict=ActionVerdict.BLOCK,
            risk_score=95.0,
            risk_level=RiskLevel.CRITICAL,
            reasons=["Destructive command prohibited."],
            matched_rule_ids=["DENY-DESTRUCTIVE-ADMIN"],
        )

        logged = self.logger.log_evaluation(req, eval_result)
        self.assertTrue(logged)

        event = self.repo.get_security_event("req-block-audit")
        self.assertIsNotNone(event)
        self.assertEqual(event.verdict, ActionVerdict.BLOCK.value)

        # Review ticket should NOT be created for BLOCK
        ticket = self.repo.get_review_ticket_by_request_id("req-block-audit")
        self.assertIsNone(ticket)

    def test_database_error_fails_safely_never_produces_allow(self) -> None:
        """Verify that a database failure raises AuditLoggingError and does NOT grant access."""
        # Point database to an invalid / read-only path to simulate persistence failure
        invalid_db = Database(db_path="/invalid_dir_path_xyz/zagentshield.db")
        broken_repo = SecurityRepository(invalid_db)
        broken_logger = AuditLogger(broken_repo)

        req = AgentRequest(
            request_id="req-fail-test",
            agent_id="agent-01",
            action="read",
            category=ActionCategory.READ,
            resource="db://test",
        )
        eval_result = SecurityEvaluation(
            request_id="req-fail-test",
            verdict=ActionVerdict.BLOCK,
            risk_score=90.0,
            risk_level=RiskLevel.CRITICAL,
            reasons=["Blocked"],
        )

        with self.assertRaises(AuditLoggingError):
            broken_logger.log_evaluation(req, eval_result)


if __name__ == "__main__":
    unittest.main()
