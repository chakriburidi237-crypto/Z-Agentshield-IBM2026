"""Unit tests for Z-AgentShield Behavioral Anomaly Detection module.

Tests sliding-window velocity tracking, repeated denial detection, resource probing,
bulk-action bursts, baseline deviation, injected clock determinism, and fail-safe integration.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from zagentshield.anomalies.detector import (
    AnomalyAssessment,
    AnomalyCode,
    AnomalyConfig,
    AnomalyDetector,
)
from zagentshield.audit.logger import AuditLogger
from zagentshield.core.enums import ActionCategory, ActionVerdict, RiskLevel
from zagentshield.core.gate import DecisionGate
from zagentshield.core.models import AgentRequest
from zagentshield.db.database import Database
from zagentshield.db.repository import SecurityEventRecord, SecurityRepository
from zagentshield.policies.engine import PolicyEngine


class TestAnomalyDetector(unittest.TestCase):
    """Test suite for AnomalyDetector behavioral algorithms and edge cases."""

    def setUp(self) -> None:
        """Set up standard fixed time and detector config."""
        self.fixed_time = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
        self.clock = lambda: self.fixed_time
        self.config = AnomalyConfig(
            window_seconds=60,
            velocity_threshold=5,
            denied_action_threshold=3,
            resource_probing_threshold=4,
            bulk_action_threshold=3,
            min_baseline_events=20,
        )
        self.detector = AnomalyDetector(config=self.config, clock=self.clock)

    def _make_event(
        self,
        req_id: str,
        seconds_ago: float,
        action: str = "query",
        category: str = ActionCategory.READ.value,
        resource: str = "db://catalog",
        verdict: str = ActionVerdict.ALLOW.value,
    ) -> SecurityEventRecord:
        """Helper to create a historical SecurityEventRecord relative to fixed_time."""
        event_time = self.fixed_time - timedelta(seconds=seconds_ago)
        return SecurityEventRecord(
            id=1,
            request_id=req_id,
            agent_id="agent-test",
            action=action,
            category=category,
            resource=resource,
            verdict=verdict,
            risk_score=10.0,
            risk_level=RiskLevel.LOW.value,
            reasons=["Routine access"],
            matched_rule_ids=["RULE-ALLOW"],
            parameters_redacted={},
            timestamp=event_time.isoformat(),
        )

    def test_normal_behavior_produces_no_anomaly(self) -> None:
        """Verify normal low-frequency requests produce an empty non-anomalous assessment."""
        req = AgentRequest(
            request_id="req-normal",
            agent_id="agent-test",
            action="query",
            category=ActionCategory.READ,
            resource="db://catalog",
            timestamp=self.fixed_time,
        )
        events = [self._make_event("req-1", seconds_ago=30)]

        assessment = self.detector.detect_anomalies(req, events=events)
        self.assertFalse(assessment.is_anomalous)
        self.assertEqual(len(assessment.signals), 0)
        self.assertEqual(assessment.composite_risk_delta, 0.0)

    def test_empty_history_produces_no_anomaly(self) -> None:
        """Verify an agent with zero history produces no anomaly."""
        req = AgentRequest(
            request_id="req-fresh",
            agent_id="agent-fresh",
            action="query",
            category=ActionCategory.READ,
            resource="db://catalog",
            timestamp=self.fixed_time,
        )
        assessment = self.detector.detect_anomalies(req, events=[])
        self.assertFalse(assessment.is_anomalous)

    def test_request_velocity_threshold(self) -> None:
        """Verify exceeding velocity threshold triggers VELOCITY_SPIKE signal."""
        # 4 events in last 40 seconds + current request = 5 (threshold is 5)
        events = [
            self._make_event(f"req-h-{i}", seconds_ago=10 * i)
            for i in range(1, 5)
        ]
        req = AgentRequest(
            request_id="req-burst",
            agent_id="agent-test",
            action="query",
            category=ActionCategory.READ,
            resource="db://catalog",
            timestamp=self.fixed_time,
        )
        assessment = self.detector.detect_anomalies(req, events=events)
        self.assertTrue(assessment.is_anomalous)
        codes = [s.code for s in assessment.signals]
        self.assertIn(AnomalyCode.VELOCITY_SPIKE, codes)
        self.assertEqual(assessment.highest_severity, RiskLevel.HIGH)
        self.assertGreaterEqual(assessment.composite_risk_delta, 25.0)

    def test_repeated_denied_action_threshold(self) -> None:
        """Verify repeated BLOCK actions within the window trigger REPEATED_DENIED."""
        # 3 blocked events in the window
        events = [
            self._make_event(f"req-denied-{i}", seconds_ago=15 * i, verdict=ActionVerdict.BLOCK.value)
            for i in range(1, 4)
        ]
        req = AgentRequest(
            request_id="req-after-denied",
            agent_id="agent-test",
            action="query",
            category=ActionCategory.READ,
            resource="db://catalog",
            timestamp=self.fixed_time,
        )
        assessment = self.detector.detect_anomalies(req, events=events)
        self.assertTrue(assessment.is_anomalous)
        codes = [s.code for s in assessment.signals]
        self.assertIn(AnomalyCode.REPEATED_DENIED, codes)
        self.assertEqual(assessment.highest_severity, RiskLevel.CRITICAL)
        self.assertGreaterEqual(assessment.composite_risk_delta, 35.0)

    def test_resource_probing_detection(self) -> None:
        """Verify accessing 4 distinct resources within window triggers RESOURCE_PROBING."""
        events = [
            self._make_event("req-res-1", seconds_ago=40, resource="api://service-a"),
            self._make_event("req-res-2", seconds_ago=30, resource="api://service-b"),
            self._make_event("req-res-3", seconds_ago=20, resource="api://service-c"),
        ]
        # Current request accesses 4th resource
        req = AgentRequest(
            request_id="req-probe",
            agent_id="agent-test",
            action="query",
            category=ActionCategory.READ,
            resource="api://service-d",
            timestamp=self.fixed_time,
        )
        assessment = self.detector.detect_anomalies(req, events=events)
        self.assertTrue(assessment.is_anomalous)
        codes = [s.code for s in assessment.signals]
        self.assertIn(AnomalyCode.RESOURCE_PROBING, codes)
        self.assertIn("probing", assessment.reasons[0].lower())

    def test_bulk_action_burst_detection(self) -> None:
        """Verify high frequency EXPORT operations trigger BULK_ACTION_BURST."""
        events = [
            self._make_event("req-export-1", seconds_ago=35, category=ActionCategory.EXPORT.value),
            self._make_event("req-export-2", seconds_ago=20, category=ActionCategory.EXPORT.value),
        ]
        # Current request is 3rd EXPORT (threshold is 3)
        req = AgentRequest(
            request_id="req-bulk-burst",
            agent_id="agent-test",
            action="export_data",
            category=ActionCategory.EXPORT,
            resource="s3://backup",
            timestamp=self.fixed_time,
        )
        assessment = self.detector.detect_anomalies(req, events=events)
        self.assertTrue(assessment.is_anomalous)
        codes = [s.code for s in assessment.signals]
        self.assertIn(AnomalyCode.BULK_ACTION_BURST, codes)

    def test_boundary_conditions_time_window(self) -> None:
        """Verify events strictly outside the window (e.g., 61s ago) are not counted."""
        # 10 events all older than window_seconds (65s ago)
        events = [
            self._make_event(f"req-old-{i}", seconds_ago=65 + i)
            for i in range(10)
        ]
        req = AgentRequest(
            request_id="req-fresh-window",
            agent_id="agent-test",
            action="query",
            category=ActionCategory.READ,
            resource="db://catalog",
            timestamp=self.fixed_time,
        )
        assessment = self.detector.detect_anomalies(req, events=events)
        # None of the old events fall in the 60s window
        self.assertFalse(assessment.is_anomalous)

    def test_utc_and_timezone_aware_timestamps(self) -> None:
        """Verify timezone-aware datetimes with non-UTC or UTC offsets parse cleanly."""
        aware_time = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
        req = AgentRequest(
            request_id="req-aware",
            agent_id="agent-test",
            action="query",
            category=ActionCategory.READ,
            resource="db://catalog",
            timestamp=aware_time,
        )
        events = [self._make_event("req-ev", seconds_ago=10)]
        assessment = self.detector.detect_anomalies(req, events=events)
        self.assertIsNotNone(assessment)

    def test_missing_or_corrupt_timestamps_handled_safely(self) -> None:
        """Verify corrupt event timestamps are handled without crashing."""
        corrupt_event = self._make_event("req-bad-ts", seconds_ago=10)
        corrupt_event.timestamp = "not-a-valid-iso-timestamp"

        req = AgentRequest(
            request_id="req-test-corrupt",
            agent_id="agent-test",
            action="query",
            category=ActionCategory.READ,
            resource="db://catalog",
            timestamp=self.fixed_time,
        )
        assessment = self.detector.detect_anomalies(req, events=[corrupt_event])
        self.assertFalse(assessment.is_anomalous)

    def test_out_of_order_timestamps(self) -> None:
        """Verify out-of-order historical events are sorted and windowed correctly."""
        # Scrambled timestamps: 10s ago, 50s ago, 20s ago, 30s ago
        events = [
            self._make_event("req-1", seconds_ago=50),
            self._make_event("req-2", seconds_ago=10),
            self._make_event("req-3", seconds_ago=30),
            self._make_event("req-4", seconds_ago=20),
        ]
        req = AgentRequest(
            request_id="req-order-test",
            agent_id="agent-test",
            action="query",
            category=ActionCategory.READ,
            resource="db://catalog",
            timestamp=self.fixed_time,
        )
        # 4 events in window + current = 5 -> Triggers velocity spike
        assessment = self.detector.detect_anomalies(req, events=events)
        codes = [s.code for s in assessment.signals]
        self.assertIn(AnomalyCode.VELOCITY_SPIKE, codes)

    def test_injected_clock_deterministic_results(self) -> None:
        """Verify that an injected clock yields bit-for-bit identical results."""
        events = [self._make_event("req-clk", seconds_ago=25)]
        req = AgentRequest(
            request_id="req-det",
            agent_id="agent-test",
            action="query",
            category=ActionCategory.READ,
            resource="db://catalog",
            timestamp=self.fixed_time,
        )
        eval1 = self.detector.detect_anomalies(req, events=events)
        eval2 = self.detector.detect_anomalies(req, events=events)
        self.assertEqual(eval1.composite_risk_delta, eval2.composite_risk_delta)
        self.assertEqual(eval1.is_anomalous, eval2.is_anomalous)

    def test_insufficient_baseline_data_skips_baseline_rule(self) -> None:
        """Verify that baseline deviation is safely skipped when history < min_baseline_events."""
        # 10 events is less than min_baseline_events (20)
        events = [self._make_event(f"req-b-{i}", seconds_ago=100 + i * 20) for i in range(10)]
        req = AgentRequest(
            request_id="req-baseline-check",
            agent_id="agent-test",
            action="query",
            category=ActionCategory.READ,
            resource="db://catalog",
            timestamp=self.fixed_time,
        )
        assessment = self.detector.detect_anomalies(req, events=events)
        codes = [s.code for s in assessment.signals]
        self.assertNotIn(AnomalyCode.BASELINE_DEVIATION, codes)

    def test_duplicate_request_id_not_counted_twice(self) -> None:
        """Verify that an event with the current request_id is not double counted."""
        # Event in history already has request_id "req-dup-id"
        dup_event = self._make_event("req-dup-id", seconds_ago=10)
        events = [dup_event]

        req = AgentRequest(
            request_id="req-dup-id",
            agent_id="agent-test",
            action="query",
            category=ActionCategory.READ,
            resource="db://catalog",
            timestamp=self.fixed_time,
        )
        assessment = self.detector.detect_anomalies(req, events=events)
        # Should only count current request once, not twice
        self.assertFalse(assessment.is_anomalous)

    def test_no_sensitive_parameters_stored_by_detector(self) -> None:
        """Verify that anomaly signal messages and details do not leak parameters."""
        events = [self._make_event(f"req-leak-{i}", seconds_ago=10 * i) for i in range(1, 5)]
        req = AgentRequest(
            request_id="req-secret-param",
            agent_id="agent-test",
            action="query",
            category=ActionCategory.READ,
            resource="db://catalog",
            parameters={"password": "raw_sensitive_password_123"},
            timestamp=self.fixed_time,
        )
        assessment = self.detector.detect_anomalies(req, events=events)
        assessment_str = str(assessment)
        self.assertNotIn("raw_sensitive_password_123", assessment_str)

    def test_detector_exception_handling_fails_safely(self) -> None:
        """Verify internal detector exceptions produce DETECTOR_ERROR without crashing."""
        # Pass a mock object that raises during iteration
        class CrashingList:
            def __iter__(self):
                raise MemoryError("Out of memory in detector")

        req = AgentRequest(
            request_id="req-crash",
            agent_id="agent-test",
            action="query",
            category=ActionCategory.READ,
            resource="db://catalog",
            timestamp=self.fixed_time,
        )
        assessment = self.detector.detect_anomalies(req, events=CrashingList())  # type: ignore[arg-type]
        self.assertTrue(assessment.is_anomalous)
        codes = [s.code for s in assessment.signals]
        self.assertIn(AnomalyCode.DETECTOR_ERROR, codes)
        self.assertGreaterEqual(assessment.composite_risk_delta, 20.0)


class TestAnomalyGateIntegration(unittest.TestCase):
    """Integration test suite connecting AnomalyDetector, PolicyEngine, and DecisionGate."""

    def setUp(self) -> None:
        """Initialize temporary database and integrated DecisionGate."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_anomaly_gate.db"
        self.db = Database(db_path=self.db_path)
        self.db.init_db()

        self.repository = SecurityRepository(self.db)
        self.audit_logger = AuditLogger(self.repository)
        self.policy_engine = PolicyEngine.from_yaml_file("config/policies.yaml")
        self.detector = AnomalyDetector(
            config=AnomalyConfig(window_seconds=60, velocity_threshold=4),
            repository=self.repository,
        )
        self.gate = DecisionGate(
            policy_engine=self.policy_engine,
            audit_logger=self.audit_logger,
            repository=self.repository,
            anomaly_detector=self.detector,
        )

    def tearDown(self) -> None:
        """Clean up temporary test directory."""
        self.temp_dir.cleanup()

    def test_anomaly_escalates_routine_allow_to_review(self) -> None:
        """Verify that high velocity escalates an otherwise permitted read to human REVIEW."""
        # Populate repository with 3 prior events in the last 20 seconds
        for i in range(3):
            self.repository.record_security_event(
                request_id=f"req-prior-{i}",
                agent_id="agent-fast",
                action="query_catalog_items",
                category=ActionCategory.READ.value,
                resource="api://catalog/products/1",
                verdict=ActionVerdict.ALLOW.value,
                risk_score=10.0,
                risk_level=RiskLevel.LOW.value,
                reasons=["Routine read"],
                matched_rule_ids=["ALLOW-CATALOG-READ"],
            )

        # 4th request reaches velocity_threshold (4)
        req = AgentRequest(
            request_id="req-trigger-anomaly",
            agent_id="agent-fast",
            action="query_catalog_items",
            category=ActionCategory.READ,
            resource="api://catalog/products/1",
        )
        result = self.gate.intercept_and_execute(
            request=req,
            trusted_permissions={"catalog.read"},
        )

        # Should be escalated to REVIEW due to VELOCITY_SPIKE anomaly
        self.assertFalse(result.allowed)
        self.assertEqual(result.verdict, ActionVerdict.REVIEW)
        self.assertTrue(any("velocity spike" in r.lower() for r in result.evaluation.reasons))

    def test_block_cannot_become_allow_due_to_anomaly_logic(self) -> None:
        """Verify that mandatory BLOCK rules are never weakened or overridden by anomaly checks."""
        req = AgentRequest(
            request_id="req-block-override-test",
            agent_id="agent-01",
            action="drop_table_customers",
            category=ActionCategory.ADMIN,
            resource="db://finance/customer_ledger",
        )
        result = self.gate.intercept_and_execute(
            request=req,
            trusted_permissions={"admin.execute"},
        )
        # Mandatory deny rule takes absolute precedence
        self.assertFalse(result.allowed)
        self.assertEqual(result.verdict, ActionVerdict.BLOCK)
        self.assertIn("DENY-DESTRUCTIVE-ADMIN", result.evaluation.matched_rule_ids)


if __name__ == "__main__":
    unittest.main()
