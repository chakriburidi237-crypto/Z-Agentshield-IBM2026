"""Unit tests for Z-AgentShield domain models, enums, and schemas.

Covers input validation, identifier constraints, risk score boundaries,
and ALLOW/REVIEW/BLOCK evaluation contracts.
"""

from datetime import datetime, timezone
import unittest
from pydantic import ValidationError

from zagentshield.core.enums import ActionCategory, ActionVerdict, RiskLevel
from zagentshield.core.models import AgentRequest, PolicyRule, SecurityEvaluation
from zagentshield.core.schemas import InterceptRequest, InterceptResponse


class TestAgentRequestModel(unittest.TestCase):
    """Tests validation constraints on AgentRequest."""

    def test_valid_agent_request(self) -> None:
        """Verify that a well-formed agent request validates cleanly."""
        req = AgentRequest(
            request_id="req-12345",
            agent_id="agent-finance-01",
            action="query_customer_balance",
            category=ActionCategory.READ,
            resource="db://banking/accounts/123",
            parameters={"account_id": "123"},
            claimed_permissions=["accounts.read"],
        )
        self.assertEqual(req.request_id, "req-12345")
        self.assertEqual(req.agent_id, "agent-finance-01")
        self.assertEqual(req.action, "query_customer_balance")
        self.assertEqual(req.category, ActionCategory.READ)
        self.assertEqual(req.resource, "db://banking/accounts/123")
        self.assertIsNotNone(req.timestamp.tzinfo)
        self.assertEqual(req.timestamp.tzinfo, timezone.utc)

    def test_missing_required_fields(self) -> None:
        """Verify that omitting required fields raises a ValidationError."""
        with self.assertRaises(ValidationError) as ctx:
            AgentRequest(  # type: ignore[call-arg]
                request_id="req-1",
                # missing agent_id
                action="read_file",
                category=ActionCategory.READ,
                resource="s3://bucket/file.txt",
            )
        self.assertIn("agent_id", str(ctx.exception))

        with self.assertRaises(ValidationError) as ctx:
            AgentRequest(  # type: ignore[call-arg]
                request_id="req-1",
                agent_id="agent-1",
                # missing action
                category=ActionCategory.READ,
                resource="s3://bucket/file.txt",
            )
        self.assertIn("action", str(ctx.exception))

    def test_malformed_identifiers(self) -> None:
        """Verify rejection of illegal characters in request_id and agent_id."""
        invalid_ids = [
            "id with spaces",
            "agent;DROP TABLE users;",
            "agent<script>",
            "agent@internal",
            "",
            "a" * 129,  # exceeds 128 chars
        ]
        for invalid_id in invalid_ids:
            with self.subTest(invalid_id=invalid_id):
                with self.assertRaises(ValidationError):
                    AgentRequest(
                        request_id=invalid_id,
                        agent_id="agent-valid",
                        action="test_action",
                        category=ActionCategory.READ,
                        resource="resource://test",
                    )
                with self.assertRaises(ValidationError):
                    AgentRequest(
                        request_id="req-valid",
                        agent_id=invalid_id,
                        action="test_action",
                        category=ActionCategory.READ,
                        resource="resource://test",
                    )

    def test_empty_or_whitespace_fields_rejected(self) -> None:
        """Verify rejection of empty or whitespace-only action and resource."""
        for blank in ["", "   ", "\t\n"]:
            with self.subTest(blank=blank):
                with self.assertRaises(ValidationError):
                    AgentRequest(
                        request_id="req-1",
                        agent_id="agent-1",
                        action=blank,
                        category=ActionCategory.READ,
                        resource="res://valid",
                    )
                with self.assertRaises(ValidationError):
                    AgentRequest(
                        request_id="req-1",
                        agent_id="agent-1",
                        action="valid_action",
                        category=ActionCategory.READ,
                        resource=blank,
                    )

    def test_extra_forbidden_fields(self) -> None:
        """Verify that unexpected extra fields are rejected."""
        with self.assertRaises(ValidationError):
            AgentRequest(
                request_id="req-1",
                agent_id="agent-1",
                action="read",
                category=ActionCategory.READ,
                resource="res://test",
                unauthorized_bypass=True,  # type: ignore[call-arg]
            )

    def test_timestamp_utc_coercion(self) -> None:
        """Verify that naive datetimes and ISO strings are coerced to UTC."""
        naive_dt = datetime(2026, 1, 15, 12, 0, 0)
        req = AgentRequest(
            request_id="req-1",
            agent_id="agent-1",
            action="read",
            category=ActionCategory.READ,
            resource="res://test",
            timestamp=naive_dt,
        )
        self.assertEqual(req.timestamp.tzinfo, timezone.utc)


class TestPolicyRuleModel(unittest.TestCase):
    """Tests validation constraints on PolicyRule."""

    def test_valid_policy_rule(self) -> None:
        """Verify valid creation of a PolicyRule."""
        rule = PolicyRule(
            rule_id="RULE-PROD-DELETE-001",
            description="Prevent unauthenticated deletions of production tables.",
            applicable_action="delete_*",
            applicable_resource="db://prod/*",
            category=ActionCategory.DELETE,
            required_permissions=["admin.delete"],
            severity=RiskLevel.CRITICAL,
            base_risk_score=90.0,
            enabled=True,
        )
        self.assertEqual(rule.rule_id, "RULE-PROD-DELETE-001")
        self.assertEqual(rule.severity, RiskLevel.CRITICAL)
        self.assertEqual(rule.base_risk_score, 90.0)
        self.assertTrue(rule.enabled)

    def test_policy_rule_id_format(self) -> None:
        """Verify policy rule_id pattern enforcement."""
        with self.assertRaises(ValidationError):
            PolicyRule(
                rule_id="INVALID RULE WITH SPACES",
                description="Test description",
                applicable_action="*",
                applicable_resource="*",
            )

    def test_policy_rule_risk_score_bounds(self) -> None:
        """Verify risk score must be between 0.0 and 100.0."""
        with self.assertRaises(ValidationError):
            PolicyRule(
                rule_id="RULE-1",
                description="Test rule",
                applicable_action="*",
                applicable_resource="*",
                base_risk_score=105.0,  # exceeds 100
            )

        with self.assertRaises(ValidationError):
            PolicyRule(
                rule_id="RULE-2",
                description="Test rule",
                applicable_action="*",
                applicable_resource="*",
                base_risk_score=-5.0,  # below 0
            )


class TestSecurityEvaluationModel(unittest.TestCase):
    """Tests validation constraints on SecurityEvaluation."""

    def test_valid_allow_evaluation(self) -> None:
        """Verify valid ALLOW decision evaluation."""
        eval_result = SecurityEvaluation(
            request_id="req-allow-01",
            verdict=ActionVerdict.ALLOW,
            risk_score=12.5,
            risk_level=RiskLevel.LOW,
            reasons=["Compliant with read-only routine access policy."],
            matched_rule_ids=["RULE-READ-DEFAULT"],
        )
        self.assertEqual(eval_result.verdict, ActionVerdict.ALLOW)
        self.assertEqual(eval_result.risk_level, RiskLevel.LOW)
        self.assertEqual(eval_result.risk_score, 12.5)

    def test_valid_review_evaluation(self) -> None:
        """Verify valid REVIEW decision evaluation."""
        eval_result = SecurityEvaluation(
            request_id="req-rev-01",
            verdict=ActionVerdict.REVIEW,
            risk_score=55.0,
            risk_level=RiskLevel.MEDIUM,
            reasons=["High-volume data export exceeds routine threshold."],
            matched_rule_ids=["RULE-HIGH-VOLUME"],
        )
        self.assertEqual(eval_result.verdict, ActionVerdict.REVIEW)
        self.assertEqual(eval_result.risk_level, RiskLevel.MEDIUM)

    def test_valid_block_evaluation(self) -> None:
        """Verify valid BLOCK decision evaluation."""
        eval_result = SecurityEvaluation(
            request_id="req-block-01",
            verdict=ActionVerdict.BLOCK,
            risk_score=95.0,
            risk_level=RiskLevel.CRITICAL,
            reasons=["Unauthorized attempt to drop production database."],
            matched_rule_ids=["RULE-PROD-DROP"],
        )
        self.assertEqual(eval_result.verdict, ActionVerdict.BLOCK)
        self.assertEqual(eval_result.risk_level, RiskLevel.CRITICAL)

    def test_invalid_risk_score_boundaries(self) -> None:
        """Verify that risk scores outside [0.0, 100.0] are rejected."""
        with self.assertRaises(ValidationError):
            SecurityEvaluation(
                request_id="req-1",
                verdict=ActionVerdict.ALLOW,
                risk_score=-1.0,
                risk_level=RiskLevel.LOW,
            )

        with self.assertRaises(ValidationError):
            SecurityEvaluation(
                request_id="req-1",
                verdict=ActionVerdict.BLOCK,
                risk_score=100.5,
                risk_level=RiskLevel.CRITICAL,
                reasons=["Test reason"],
            )

    def test_block_and_review_require_reasons(self) -> None:
        """Verify that BLOCK and REVIEW decisions must provide explanatory reasons."""
        with self.assertRaises(ValidationError) as ctx:
            SecurityEvaluation(
                request_id="req-1",
                verdict=ActionVerdict.BLOCK,
                risk_score=90.0,
                risk_level=RiskLevel.HIGH,
                reasons=[],  # missing reason
            )
        self.assertIn("must include at least one explanatory reason", str(ctx.exception))

        with self.assertRaises(ValidationError) as ctx:
            SecurityEvaluation(
                request_id="req-2",
                verdict=ActionVerdict.REVIEW,
                risk_score=50.0,
                risk_level=RiskLevel.MEDIUM,
                reasons=[],  # missing reason
            )
        self.assertIn("must include at least one explanatory reason", str(ctx.exception))


class TestSchemas(unittest.TestCase):
    """Tests API-facing InterceptRequest and InterceptResponse schemas."""

    def test_intercept_request_conversion(self) -> None:
        """Verify conversion of InterceptRequest to domain AgentRequest."""
        incoming = InterceptRequest(
            agent_id="agent-order-01",
            action="submit_order",
            category=ActionCategory.WRITE,
            resource="api://orders/new",
            parameters={"order_id": 999, "api_key": "raw_secret_value"},
        )
        domain_req = incoming.to_agent_request()
        self.assertTrue(domain_req.request_id.startswith("req-"))
        self.assertEqual(domain_req.agent_id, "agent-order-01")
        self.assertEqual(domain_req.action, "submit_order")
        self.assertEqual(domain_req.category, ActionCategory.WRITE)

    def test_intercept_response_from_evaluation(self) -> None:
        """Verify InterceptResponse construction hides parameters and sets convenience flags."""
        eval_result = SecurityEvaluation(
            request_id="req-test-99",
            verdict=ActionVerdict.ALLOW,
            risk_score=15.0,
            risk_level=RiskLevel.LOW,
            reasons=["Safe action verified."],
            matched_rule_ids=["RULE-DEFAULT-ALLOW"],
        )
        response = InterceptResponse.from_evaluation(eval_result)
        self.assertEqual(response.request_id, "req-test-99")
        self.assertEqual(response.verdict, ActionVerdict.ALLOW)
        self.assertTrue(response.allowed)
        self.assertFalse(response.review_required)
        self.assertEqual(response.risk_score, 15.0)
        self.assertNotIn("parameters", response.model_dump())


if __name__ == "__main__":
    unittest.main()
