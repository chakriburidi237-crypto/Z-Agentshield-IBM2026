"""Unit tests for Z-AgentShield Policy Engine and Risk Scoring.

Verifies deterministic gating, mandatory deny enforcement, trusted authorization checks,
risk score boundary limits, and fail-closed configuration handling.
"""

from pathlib import Path
import tempfile
import unittest

from zagentshield.core.enums import ActionCategory, ActionVerdict, RiskLevel
from zagentshield.core.models import AgentRequest, PolicyRule
from zagentshield.policies.engine import (
    PolicyConfig,
    PolicyConfigurationError,
    PolicyEngine,
)
from zagentshield.policies.risk_scoring import RiskScorer


class TestPolicyEngine(unittest.TestCase):
    """Test suite for policy engine evaluation and risk scoring."""

    def setUp(self) -> None:
        """Initialize engine from default policies configuration."""
        self.policy_file = Path("config/policies.yaml")
        self.engine = PolicyEngine.from_yaml_file(self.policy_file)

    def test_explicitly_permitted_authorized_read(self) -> None:
        """Verify an allowed read request with valid trusted credentials evaluates to ALLOW."""
        request = AgentRequest(
            request_id="req-allow-01",
            agent_id="agent-catalog-assistant",
            action="query_catalog_items",
            category=ActionCategory.READ,
            resource="api://catalog/products/123",
            parameters={"query": "electronics"},
            claimed_permissions=["catalog.read"],
        )
        trusted_perms = {"catalog.read"}

        eval_result = self.engine.evaluate(request, trusted_permissions=trusted_perms)
        self.assertEqual(eval_result.verdict, ActionVerdict.ALLOW)
        self.assertEqual(eval_result.risk_level, RiskLevel.LOW)
        self.assertLess(eval_result.risk_score, 40.0)
        self.assertIn("ALLOW-CATALOG-READ", eval_result.matched_rule_ids)

    def test_unauthorized_access_to_restricted_resource(self) -> None:
        """Verify direct access to secrets/vaults is immediately BLOCKED by mandatory deny."""
        request = AgentRequest(
            request_id="req-deny-secrets",
            agent_id="agent-rogue",
            action="get_credentials",
            category=ActionCategory.READ,
            resource="secrets://production/db_master_key",
            parameters={},
            claimed_permissions=["admin.all"],
        )
        # Even with claimed admin permissions, mandatory deny takes absolute precedence
        eval_result = self.engine.evaluate(request, trusted_permissions={"admin.all"})
        self.assertEqual(eval_result.verdict, ActionVerdict.BLOCK)
        self.assertIn("DENY-RAW-SECRETS", eval_result.matched_rule_ids)
        self.assertEqual(eval_result.risk_level, RiskLevel.CRITICAL)
        self.assertGreaterEqual(eval_result.risk_score, 75.0)

    def test_prohibited_destructive_operation(self) -> None:
        """Verify destructive database operations are BLOCKED regardless of agent claims."""
        request = AgentRequest(
            request_id="req-deny-drop",
            agent_id="agent-dev-01",
            action="drop_table_customers",
            category=ActionCategory.ADMIN,
            resource="db://finance/customer_ledger",
            parameters={},
        )
        eval_result = self.engine.evaluate(request, trusted_permissions={"admin.execute"})
        self.assertEqual(eval_result.verdict, ActionVerdict.BLOCK)
        self.assertIn("DENY-DESTRUCTIVE-ADMIN", eval_result.matched_rule_ids)

    def test_bulk_export_requiring_review(self) -> None:
        """Verify that high-volume bulk exports escalate to REVIEW for human verification."""
        request = AgentRequest(
            request_id="req-export-01",
            agent_id="agent-analyst",
            action="export_customer_data",
            category=ActionCategory.EXPORT,
            resource="s3://backups/customers_2026.csv",
            parameters={"limit": 50000, "bulk": True},
            claimed_permissions=["export.data"],
        )
        trusted_perms = {"export.data"}

        eval_result = self.engine.evaluate(request, trusted_permissions=trusted_perms)
        self.assertEqual(eval_result.verdict, ActionVerdict.REVIEW)
        self.assertIn("REV-BULK-DATA-EXPORT", eval_result.matched_rule_ids)
        self.assertTrue(len(eval_result.reasons) > 0)

    def test_missing_trusted_authorization(self) -> None:
        """Verify request claiming a permission without trusted backing is BLOCKED."""
        request = AgentRequest(
            request_id="req-untrusted-claim",
            agent_id="agent-sales",
            action="query_report",
            category=ActionCategory.READ,
            resource="db://reporting/quarterly_sales",
            parameters={},
            claimed_permissions=["reports.read"],  # Agent claims permission
        )
        # Trusted credentials do NOT contain 'reports.read'
        trusted_perms: set[str] = set()

        eval_result = self.engine.evaluate(request, trusted_permissions=trusted_perms)
        self.assertEqual(eval_result.verdict, ActionVerdict.BLOCK)
        self.assertTrue(
            any("Missing trusted authorization" in r for r in eval_result.reasons),
            f"Reasons did not mention missing authorization: {eval_result.reasons}",
        )

    def test_unknown_resource_or_action_default_deny(self) -> None:
        """Verify that unmatched actions fall back to default-deny (BLOCK)."""
        request = AgentRequest(
            request_id="req-unmatched-01",
            agent_id="agent-general",
            action="custom_unknown_action",
            category=ActionCategory.WRITE,
            resource="api://internal/proprietary_service",
            parameters={},
        )
        eval_result = self.engine.evaluate(request, trusted_permissions=set())
        self.assertEqual(eval_result.verdict, ActionVerdict.BLOCK)
        self.assertTrue(
            any("Default-Deny" in r for r in eval_result.reasons),
            f"Reasons did not mention Default-Deny: {eval_result.reasons}",
        )

    def test_invalid_policy_configuration_fails_closed(self) -> None:
        """Verify that invalid policy configuration files raise PolicyConfigurationError."""
        # Non-existent file
        with self.assertRaises(PolicyConfigurationError):
            PolicyEngine.from_yaml_file("config/non_existent_file.yaml")

        # Corrupt / invalid YAML structure
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tmp:
            tmp.write("invalid_yaml: [unclosed list\n")
            tmp_path = tmp.name

        try:
            with self.assertRaises(PolicyConfigurationError):
                PolicyEngine.from_yaml_file(tmp_path)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        # Schema validation error
        with self.assertRaises(PolicyConfigurationError):
            PolicyEngine.from_dict({"deny_rules": "not a list of rules"})

    def test_risk_score_boundaries(self) -> None:
        """Verify that risk scores always remain strictly within [0.0, 100.0]."""
        scorer = RiskScorer()
        test_requests = [
            AgentRequest(
                request_id="req-min",
                agent_id="agent-01",
                action="get_info",
                category=ActionCategory.READ,
                resource="api://public",
            ),
            AgentRequest(
                request_id="req-max",
                agent_id="agent-02",
                action="drop_table",
                category=ActionCategory.ADMIN,
                resource="secrets://master/key",
                parameters={"query": "DROP TABLE users;--", "limit": 999999, "all": True},
                claimed_permissions=["admin.all"],
            ),
        ]
        for req in test_requests:
            with self.subTest(request_id=req.request_id):
                assessment = scorer.evaluate_risk(req, trusted_permissions=set())
                self.assertGreaterEqual(assessment.risk_score, 0.0)
                self.assertLessEqual(assessment.risk_score, 100.0)
                self.assertIn(assessment.risk_level, list(RiskLevel))

    def test_mandatory_block_never_overridden_by_low_risk_score(self) -> None:
        """Verify that a mandatory deny rule CANNOT be overridden even if risk score is low."""
        # Custom engine where deny rule has low base risk score
        custom_config = PolicyConfig(
            deny_rules=[
                PolicyRule(
                    rule_id="RULE-PROHIBIT-TEST",
                    description="Prohibit test operation.",
                    applicable_action="forbidden_test",
                    applicable_resource="*",
                    category=ActionCategory.READ,
                    base_risk_score=5.0,  # Deliberately low base risk
                    severity=RiskLevel.LOW,
                )
            ],
            allow_rules=[],
        )
        engine = PolicyEngine(config=custom_config)
        request = AgentRequest(
            request_id="req-deny-low-risk",
            agent_id="agent-01",
            action="forbidden_test",
            category=ActionCategory.READ,
            resource="res://public",
        )
        eval_result = engine.evaluate(request, trusted_permissions={"some.perm"})
        # Must still be BLOCK regardless of score
        self.assertEqual(eval_result.verdict, ActionVerdict.BLOCK)
        self.assertIn("RULE-PROHIBIT-TEST", eval_result.matched_rule_ids)

    def test_deterministic_evaluation(self) -> None:
        """Verify that identical inputs produce identical evaluations."""
        request = AgentRequest(
            request_id="req-repeat-01",
            agent_id="agent-fixed",
            action="query_catalog_items",
            category=ActionCategory.READ,
            resource="api://catalog/items/456",
            parameters={"filter": "books"},
            claimed_permissions=["catalog.read"],
        )
        trusted_perms = {"catalog.read"}

        eval1 = self.engine.evaluate(request, trusted_permissions=trusted_perms)
        eval2 = self.engine.evaluate(request, trusted_permissions=trusted_perms)

        self.assertEqual(eval1.verdict, eval2.verdict)
        self.assertEqual(eval1.risk_score, eval2.risk_score)
        self.assertEqual(eval1.risk_level, eval2.risk_level)
        self.assertEqual(eval1.matched_rule_ids, eval2.matched_rule_ids)
        self.assertEqual(eval1.reasons, eval2.reasons)


if __name__ == "__main__":
    unittest.main()
