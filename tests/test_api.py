"""Tests for Z-AgentShield Phase 7: FastAPI Security Gateway.

Uses FastAPI TestClient with injected, isolated in-memory SQLite databases.
Never depends on external services, files, or credentials.

Security invariants verified:
- BLOCK never invokes callbacks or returns 2xx with allowed=True.
- REVIEW never auto-executes; always returns a ticket_id.
- Audit failures produce fail-closed BLOCK responses.
- Client-supplied reviewer identity fields are ignored; only X-Reviewer-Id header counts.
- Sensitive parameters are not echoed in responses.
- Unauthenticated privileged endpoints return 401.
- Policy engine exceptions fail closed.
- Unexpected exceptions return 500, never 200.
"""

import sqlite3
import os
import unittest
import warnings
from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional
from unittest.mock import MagicMock, patch

# Suppress the httpx2 starlette deprecation warning (cosmetic; TestClient still works)
warnings.filterwarnings("ignore", category=DeprecationWarning, module="starlette")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="httpx")

from fastapi.testclient import TestClient

from zagentshield.anomalies.detector import AnomalyConfig, AnomalyDetector
from zagentshield.audit.logger import AuditLogger, AuditLoggingError
from zagentshield.core.enums import ActionCategory, ActionVerdict, RiskLevel
from zagentshield.core.models import AgentRequest, SecurityEvaluation
from zagentshield.db.database import Database, SCHEMA_SQL
from zagentshield.db.repository import SecurityRepository
from zagentshield.policies.engine import PolicyEngine
from zagentshield.config import get_settings


# ---------------------------------------------------------------------------
# Shared-connection in-memory Database for tests
# ---------------------------------------------------------------------------
# sqlite3.connect(":memory:") creates a NEW empty database on every call.
# Tests need multiple connections all pointing at the SAME in-memory database.
# We hold a single connection open for the lifetime of each test and reuse it.

class _SharedMemoryDatabase(Database):
    """In-memory SQLite database that reuses a single connection for all operations.

    Standard Database creates a new connection (and thus a new empty in-memory
    DB) for every operation. This subclass holds one persistent connection so
    all operations within a test share the same schema and data.
    """

    def __init__(self) -> None:
        super().__init__(":memory:")
        self._conn: sqlite3.Connection = sqlite3.connect(
            ":memory:", check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON;")
        # Initialise schema immediately
        self._conn.executescript(SCHEMA_SQL)
        self._conn.commit()

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield the shared connection without closing it."""
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def init_db(self) -> None:
        """No-op: schema already initialised in __init__."""

    def close(self) -> None:
        """Explicitly close the persistent connection."""
        try:
            self._conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def _default_policy_data() -> Dict[str, Any]:
    return {
        "version": "1.0",
        "default_verdict": "BLOCK",
        "deny_rules": [
            {
                "rule_id": "deny-delete-all",
                "description": "Prohibit bulk delete operations",
                "applicable_action": "delete_all",
                "applicable_resource": "*",
                "category": "DELETE",
                "severity": "CRITICAL",
                "base_risk_score": 95.0,
            },
            {
                "rule_id": "deny-secrets",
                "description": "Prohibit access to secrets vault",
                "applicable_action": "*",
                "applicable_resource": "secrets/vault",
                "severity": "CRITICAL",
                "base_risk_score": 100.0,
            },
        ],
        "review_rules": [
            {
                "rule_id": "review-export",
                "description": "Bulk data export requires human review",
                "applicable_action": "export_data",
                "applicable_resource": "*",
                "category": "EXPORT",
                "severity": "HIGH",
                "base_risk_score": 60.0,
            },
        ],
        "allow_rules": [
            {
                "rule_id": "allow-read",
                "description": "Read operations on public resources are permitted",
                "applicable_action": "read_record",
                "applicable_resource": "public/*",
                "category": "READ",
                "severity": "LOW",
                "base_risk_score": 5.0,
            },
        ],
    }


def _trusted_test_resource(_request: AgentRequest) -> bool:
    """Represent an injected trusted resource directory in API tests."""
    return True


def _make_services(
    policy_data: Optional[Dict[str, Any]] = None,
    audit_logger_override=None,
    anomaly_detector_override=None,
    resource_classifier=_trusted_test_resource,
):
    """Build an AppServices graph backed by a shared in-memory SQLite database."""
    from zagentshield.api.app import AppServices

    db = _SharedMemoryDatabase()
    repo = SecurityRepository(db)
    audit = audit_logger_override or AuditLogger(repo)
    engine = PolicyEngine.from_dict(policy_data or _default_policy_data())
    detector = anomaly_detector_override or AnomalyDetector(
        config=AnomalyConfig(), repository=repo
    )
    return AppServices(
        policy_engine=engine,
        repository=repo,
        audit_logger=audit,
        anomaly_detector=detector,
        resource_classifier=resource_classifier,
    )


def _make_client(services=None) -> TestClient:
    from zagentshield.api.app import create_app
    svc = services or _make_services()
    return TestClient(create_app(services=svc), raise_server_exceptions=False)


def _allow_body(**overrides) -> Dict[str, Any]:
    base = {
        "agent_id": "agent-test-001",
        "action": "read_record",
        "category": "READ",
        "resource": "public/reports/q1",
        "parameters": {"format": "json"},
        "claimed_permissions": [],
        "context": {"session": "sess-abc"},
    }
    base.update(overrides)
    return base


REVIEW_BODY: Dict[str, Any] = {
    "agent_id": "agent-export-001",
    "action": "export_data",
    "category": "EXPORT",
    "resource": "reports/2024",
    "parameters": {},
}

BLOCK_BODY: Dict[str, Any] = {
    "agent_id": "agent-evil-001",
    "action": "delete_all",
    "category": "DELETE",
    "resource": "users/table",
    "parameters": {},
}


# ---------------------------------------------------------------------------
# Test Suite
# ---------------------------------------------------------------------------


class TestHealthEndpoint(unittest.TestCase):
    """GET /health"""

    def setUp(self):
        self.client = _make_client()

    def test_health_returns_200(self):
        """Health endpoint returns HTTP 200."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)

    def test_health_response_structure(self):
        """Health response has status, version, and timestamp."""
        data = self.client.get("/health").json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("version", data)
        self.assertIn("timestamp", data)

    def test_health_does_not_expose_config_secrets(self):
        """Health response never contains DB path, env keys, or secret values."""
        body = self.client.get("/health").text
        self.assertNotIn("database_path", body)
        self.assertNotIn("policy_config_path", body)
        self.assertNotIn("secret", body.lower())

    def test_root_returns_200_and_links(self):
        """Root endpoint returns HTTP 200 with service info and docs/health links."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["service"], "Z-AgentShield Security Gateway")
        self.assertEqual(data["status"], "active")
        self.assertIn("docs", data)
        self.assertIn("health", data)

    def test_api_docs_are_available_in_development(self):
        from zagentshield.api.app import create_app

        with patch.dict(os.environ, {"APP_ENV": "development"}):
            get_settings.cache_clear()
            client = TestClient(create_app(services=_make_memory_services()))
            self.assertEqual(client.get("/docs").status_code, 200)
            self.assertEqual(client.get("/openapi.json").status_code, 200)
            self.assertEqual(client.get("/").json()["docs"], "/docs")
        get_settings.cache_clear()

    def test_api_docs_and_openapi_are_disabled_outside_development(self):
        from zagentshield.api.app import create_app

        for environment in ("demo", "production"):
            with self.subTest(environment=environment):
                with patch.dict(os.environ, {"APP_ENV": environment}):
                    get_settings.cache_clear()
                    client = TestClient(create_app(services=_make_memory_services()))
                    self.assertEqual(client.get("/docs").status_code, 404)
                    self.assertEqual(client.get("/openapi.json").status_code, 404)
                    self.assertIsNone(client.get("/").json()["docs"])
                    self.assertEqual(client.get("/health").status_code, 200)
        get_settings.cache_clear()

    def test_api_docs_are_disabled_when_environment_is_unset(self):
        from zagentshield.api.app import create_app

        try:
            with patch.dict(os.environ, {}, clear=True):
                get_settings.cache_clear()
                client = TestClient(create_app(services=_make_memory_services()))
                self.assertEqual(client.get("/docs").status_code, 404)
                self.assertEqual(client.get("/openapi.json").status_code, 404)
                self.assertIsNone(client.get("/").json()["docs"])
        finally:
            get_settings.cache_clear()


class TestInterceptAllow(unittest.TestCase):
    """POST /api/v1/intercept — ALLOW cases"""

    def setUp(self):
        self.client = _make_client()

    def test_valid_allow_request_returns_200(self):
        """Valid read request against allow rule → 200 ALLOW."""
        resp = self.client.post("/api/v1/intercept", json=_allow_body())
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["verdict"], "ALLOW")
        self.assertTrue(data["allowed"])
        self.assertFalse(data["review_required"])
        self.assertIsNone(data.get("ticket_id"))

    def test_policy_allow_is_blocked_without_trusted_resource_classifier(self):
        client = _make_client(_make_services(resource_classifier=None))

        response = client.post(
            "/api/v1/intercept",
            json=_allow_body(request_id="req-unclassified-resource"),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["verdict"], "BLOCK")
        self.assertFalse(response.json()["allowed"])
        self.assertIn(
            "Trusted resource classification is not configured",
            " ".join(response.json()["reasons"]),
        )

    def test_policy_allow_is_blocked_when_trusted_classifier_rejects_resource(self):
        client = _make_client(
            _make_services(resource_classifier=lambda _request: False)
        )

        response = client.post(
            "/api/v1/intercept",
            json=_allow_body(request_id="req-unverified-resource"),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["verdict"], "BLOCK")
        self.assertFalse(response.json()["allowed"])

    def test_duplicate_allow_is_blocked_when_resource_classifier_is_missing(self):
        services = _make_services(resource_classifier=None)
        body = _allow_body(request_id="req-old-allow")
        services.repository.record_security_event(
            request_id=body["request_id"],
            agent_id=body["agent_id"],
            action=body["action"],
            category=body["category"],
            resource=body["resource"],
            verdict="ALLOW",
            risk_score=5.0,
            risk_level="LOW",
            reasons=["Previously allowed by policy."],
            matched_rule_ids=["allow-read"],
        )
        client = _make_client(services)

        response = client.post("/api/v1/intercept", json=body)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["verdict"], "BLOCK")
        self.assertFalse(response.json()["allowed"])

    def test_allow_response_has_complete_schema(self):
        """ALLOW response contains all required schema fields."""
        data = self.client.post(
            "/api/v1/intercept", json=_allow_body(request_id="req-schema-001")
        ).json()
        for field in [
            "request_id", "verdict", "allowed", "review_required",
            "risk_score", "risk_level", "reasons", "matched_rule_ids", "evaluated_at",
        ]:
            self.assertIn(field, data, f"Missing required field: {field}")

    def test_risk_score_in_valid_range(self):
        """risk_score is always within [0.0, 100.0]."""
        score = self.client.post(
            "/api/v1/intercept", json=_allow_body(request_id="req-score-001")
        ).json()["risk_score"]
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 100.0)


class TestInterceptBlock(unittest.TestCase):
    """POST /api/v1/intercept — BLOCK cases"""

    def setUp(self):
        self.client = _make_client()

    def test_block_request_returns_200_block_verdict(self):
        """Blocked action returns 200 with BLOCK verdict and allowed=False."""
        resp = self.client.post("/api/v1/intercept", json=BLOCK_BODY)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["verdict"], "BLOCK")
        self.assertFalse(data["allowed"])
        self.assertFalse(data["review_required"])

    def test_claimed_permissions_cannot_bypass_block(self):
        """Unverified claimed_permissions in body cannot override mandatory BLOCK."""
        body = BLOCK_BODY.copy()
        body["claimed_permissions"] = ["admin", "allow_all", "bypass_security"]
        data = self.client.post("/api/v1/intercept", json=body).json()
        self.assertEqual(data["verdict"], "BLOCK")
        self.assertFalse(data["allowed"])

    def test_mandatory_deny_rule_blocks_secrets_vault(self):
        """Mandatory deny rule for secrets/vault is never bypassed."""
        body = {
            "agent_id": "agent-spy",
            "action": "read_secret",
            "category": "READ",
            "resource": "secrets/vault",
            "claimed_permissions": ["admin", "read_secrets"],
        }
        data = self.client.post("/api/v1/intercept", json=body).json()
        self.assertEqual(data["verdict"], "BLOCK")
        self.assertFalse(data["allowed"])


class TestInterceptReview(unittest.TestCase):
    """POST /api/v1/intercept — REVIEW cases"""

    def setUp(self):
        self.client = _make_client()

    def test_review_returns_200_with_ticket(self):
        """REVIEW verdict returns 200, review_required=True, and a ticket_id."""
        resp = self.client.post("/api/v1/intercept", json=REVIEW_BODY)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["verdict"], "REVIEW")
        self.assertFalse(data["allowed"])
        self.assertTrue(data["review_required"])
        self.assertIsNotNone(data.get("ticket_id"))
        self.assertTrue(data["ticket_id"].startswith("tkt-"))

    def test_review_never_has_allowed_true(self):
        """REVIEW verdict must always have allowed=False."""
        data = self.client.post("/api/v1/intercept", json=REVIEW_BODY).json()
        self.assertFalse(data["allowed"])


class TestInterceptSecurity(unittest.TestCase):
    """POST /api/v1/intercept — security invariants"""

    def setUp(self):
        self.client = _make_client()

    def test_sensitive_parameters_not_echoed(self):
        """Response must never echo raw parameter values submitted by the caller."""
        body = _allow_body(
            request_id="req-sensitive-001",
            parameters={"api_key": "super-secret-key-1234", "password": "hunter2"},
        )
        resp = self.client.post("/api/v1/intercept", json=body)
        self.assertEqual(resp.status_code, 200)
        text = resp.text
        self.assertNotIn("super-secret-key-1234", text)
        self.assertNotIn("hunter2", text)

    def test_invalid_schema_missing_required_fields_returns_422(self):
        """Request missing required fields returns 422."""
        resp = self.client.post("/api/v1/intercept", json={"agent_id": "only-this"})
        self.assertEqual(resp.status_code, 422)

    def test_extra_fields_rejected_returns_422(self):
        """Extra unexpected fields return 422 (extra='forbid' on schema)."""
        body = _allow_body(request_id="req-extra-001")
        body["injected_admin_flag"] = True
        resp = self.client.post("/api/v1/intercept", json=body)
        self.assertEqual(resp.status_code, 422)

    def test_idempotency_duplicate_request_id(self):
        """Duplicate request_id returns same verdict without re-evaluating."""
        body = _allow_body(request_id="req-dedup-001")
        resp1 = self.client.post("/api/v1/intercept", json=body)
        resp2 = self.client.post("/api/v1/intercept", json=body)
        self.assertEqual(resp1.status_code, 200)
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(resp1.json()["verdict"], resp2.json()["verdict"])

    def test_error_responses_never_expose_stack_traces(self):
        """Validation errors must not leak Python tracebacks."""
        resp = self.client.post("/api/v1/intercept", json={"bad": "input"})
        self.assertNotIn("Traceback", resp.text)
        self.assertNotIn("raise ", resp.text)

    def test_policy_engine_exception_fails_closed_500(self):
        """Policy engine exception → 500, never ALLOW."""
        from zagentshield.api.app import AppServices, create_app

        broken_engine = MagicMock()
        broken_engine.evaluate.side_effect = RuntimeError("policy crash")
        db = _SharedMemoryDatabase()
        repo = SecurityRepository(db)
        svc = AppServices(
            policy_engine=broken_engine,
            repository=repo,
            audit_logger=AuditLogger(repo),
            anomaly_detector=None,
        )
        client = TestClient(create_app(services=svc), raise_server_exceptions=False)
        resp = client.post("/api/v1/intercept", json=_allow_body())
        self.assertEqual(resp.status_code, 500)
        self.assertNotIn("ALLOW", resp.text)
        self.assertNotIn('"allowed": true', resp.text)

    def test_audit_failure_fails_closed_500(self):
        """Audit logging failure → 500, never ALLOW."""
        from zagentshield.api.app import AppServices, create_app

        broken_audit = MagicMock()
        broken_audit.log_evaluation.side_effect = AuditLoggingError("disk full")
        db = _SharedMemoryDatabase()
        repo = SecurityRepository(db)
        svc = AppServices(
            policy_engine=PolicyEngine.from_dict(_default_policy_data()),
            repository=repo,
            audit_logger=broken_audit,
            anomaly_detector=None,
        )
        client = TestClient(create_app(services=svc), raise_server_exceptions=False)
        resp = client.post("/api/v1/intercept", json=_allow_body())
        self.assertEqual(resp.status_code, 500)
        self.assertNotIn("ALLOW", resp.text)

    def test_internal_exception_returns_500_not_traceback(self):
        """Unexpected server exceptions return 500 without leaking details."""
        from zagentshield.api.app import AppServices, create_app

        broken_engine = MagicMock()
        broken_engine.evaluate.side_effect = MemoryError("OOM simulated")
        db = _SharedMemoryDatabase()
        repo = SecurityRepository(db)
        svc = AppServices(
            policy_engine=broken_engine,
            repository=repo,
            audit_logger=AuditLogger(repo),
            anomaly_detector=None,
        )
        client = TestClient(create_app(services=svc), raise_server_exceptions=False)
        resp = client.post("/api/v1/intercept", json=_allow_body())
        self.assertEqual(resp.status_code, 500)
        self.assertNotIn("Traceback", resp.text)
        self.assertNotIn("MemoryError", resp.text)


class TestDecisionLookup(unittest.TestCase):
    """GET /api/v1/decisions/{request_id}"""

    def setUp(self):
        self.svc = _make_services()
        self.client = _make_client(self.svc)
        # Seed one recorded decision
        self.client.post(
            "/api/v1/intercept",
            json=_allow_body(request_id="req-lookup-seed"),
        )

    def test_lookup_existing_decision_returns_200(self):
        """Recorded decision is retrievable by request_id."""
        resp = self.client.get("/api/v1/decisions/req-lookup-seed")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["request_id"], "req-lookup-seed")

    def test_lookup_missing_decision_returns_404(self):
        """Non-existent request_id returns 404."""
        resp = self.client.get("/api/v1/decisions/req-does-not-exist-xyz")
        self.assertEqual(resp.status_code, 404)

    def test_decision_response_has_no_raw_parameters(self):
        """Response does not include raw parameters or parameters_redacted."""
        resp = self.client.get("/api/v1/decisions/req-lookup-seed")
        data = resp.json()
        self.assertNotIn("parameters", data)
        self.assertNotIn("parameters_redacted", data)

    def test_decision_response_schema(self):
        """Decision response contains all required fields."""
        data = self.client.get("/api/v1/decisions/req-lookup-seed").json()
        for field in ["id", "request_id", "agent_id", "action", "verdict",
                      "risk_score", "risk_level", "reasons", "timestamp"]:
            self.assertIn(field, data, f"Missing field: {field}")


class TestReviewList(unittest.TestCase):
    """GET /api/v1/reviews"""

    def setUp(self):
        self.svc = _make_services()
        self.client = _make_client(self.svc)

    def test_empty_when_no_pending_tickets(self):
        """Review list is empty when no REVIEW actions have been processed."""
        resp = self.client.get("/api/v1/reviews")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])

    def test_returns_pending_ticket(self):
        """Review list returns pending tickets after a REVIEW-verdict intercept."""
        self.client.post("/api/v1/intercept", json=REVIEW_BODY)
        resp = self.client.get("/api/v1/reviews")
        self.assertEqual(resp.status_code, 200)
        tickets = resp.json()
        self.assertGreater(len(tickets), 0)
        self.assertEqual(tickets[0]["status"], "PENDING")

    def test_pagination_limit_respected(self):
        """Limit query param is respected."""
        for i in range(3):
            body = REVIEW_BODY.copy()
            body["request_id"] = f"req-page-{i:03d}"
            self.client.post("/api/v1/intercept", json=body)
        resp = self.client.get("/api/v1/reviews?limit=2")
        self.assertEqual(resp.status_code, 200)
        self.assertLessEqual(len(resp.json()), 2)

    def test_limit_above_max_rejected_422(self):
        """limit > MAX_PAGE_SIZE returns 422."""
        resp = self.client.get("/api/v1/reviews?limit=9999")
        self.assertEqual(resp.status_code, 422)

    def test_ticket_schema(self):
        """Review ticket response has all required fields."""
        self.client.post("/api/v1/intercept", json=REVIEW_BODY)
        ticket = self.client.get("/api/v1/reviews").json()[0]
        for field in ["ticket_id", "request_id", "agent_id", "action",
                      "status", "risk_score", "risk_level", "reasons",
                      "created_at", "updated_at"]:
            self.assertIn(field, ticket, f"Missing field: {field}")


class TestReviewDecision(unittest.TestCase):
    """POST /api/v1/reviews/{ticket_id}/decision"""

    def setUp(self):
        self.svc = _make_services()
        self.client = _make_client(self.svc)
        resp = self.client.post("/api/v1/intercept", json=REVIEW_BODY)
        self.ticket_id = resp.json().get("ticket_id")
        self.assertIsNotNone(self.ticket_id, "Setup: failed to create review ticket")

    def _decide(self, decision: str, reviewer: str = "reviewer-alice",
                notes: Optional[str] = None) -> Any:
        body: Dict[str, Any] = {"decision": decision}
        if notes:
            body["reviewer_notes"] = notes
        return self.client.post(
            f"/api/v1/reviews/{self.ticket_id}/decision",
            json=body,
            headers={"X-Reviewer-Id": reviewer},
        )

    def test_approve_ticket_succeeds(self):
        """APPROVED decision returns 200 with updated status."""
        resp = self._decide("APPROVED", notes="Manually verified.")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "APPROVED")
        self.assertEqual(data["reviewer_id"], "reviewer-alice")

    def test_reject_ticket_succeeds(self):
        """REJECTED decision returns 200 with updated status."""
        resp = self._decide("REJECTED")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "REJECTED")

    def test_missing_reviewer_header_returns_401(self):
        """Missing X-Reviewer-Id returns 401."""
        resp = self.client.post(
            f"/api/v1/reviews/{self.ticket_id}/decision",
            json={"decision": "APPROVED"},
        )
        self.assertEqual(resp.status_code, 401)

    def test_client_supplied_fake_reviewer_in_body_rejected(self):
        """Extra body fields (like fake_reviewer) are rejected with 422.
        The ticket must remain PENDING after the failed request."""
        resp = self.client.post(
            f"/api/v1/reviews/{self.ticket_id}/decision",
            json={"decision": "APPROVED", "fake_reviewer": "attacker"},
            headers={"X-Reviewer-Id": "reviewer-bob"},
        )
        # 'fake_reviewer' is an extra field → schema validation rejects it
        self.assertEqual(resp.status_code, 422)
        # Ticket must still be PENDING — no side effect from the failed request
        ticket = self.svc.repository.get_review_ticket(self.ticket_id)
        self.assertEqual(ticket.status, "PENDING")

    def test_invalid_decision_value_returns_400(self):
        """Invalid decision string returns 400."""
        resp = self._decide("MAYBE")
        self.assertEqual(resp.status_code, 400)

    def test_double_decision_returns_409(self):
        """Re-deciding an already terminal ticket returns 409."""
        self._decide("APPROVED")
        resp = self._decide("REJECTED")
        self.assertEqual(resp.status_code, 409)

    def test_nonexistent_ticket_returns_404(self):
        """Decision on a non-existent ticket_id returns 404."""
        resp = self.client.post(
            "/api/v1/reviews/tkt-does-not-exist/decision",
            json={"decision": "APPROVED"},
            headers={"X-Reviewer-Id": "reviewer-alice"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_approve_does_not_auto_execute_callback(self):
        """Approving a ticket changes status only — no execution_result in response."""
        resp = self._decide("APPROVED")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertNotIn("execution_result", data)
        self.assertEqual(data["status"], "APPROVED")


class TestAuditLogs(unittest.TestCase):
    """GET /api/v1/audit/logs"""

    def setUp(self):
        self.svc = _make_services()
        self.client = _make_client(self.svc)
        self.client.post("/api/v1/intercept", json=_allow_body(request_id="req-audit-seed"))

    def test_unauthenticated_access_returns_401(self):
        """Missing X-Reviewer-Id returns 401."""
        resp = self.client.get("/api/v1/audit/logs")
        self.assertEqual(resp.status_code, 401)

    def test_empty_reviewer_id_returns_401(self):
        """Empty X-Reviewer-Id header is treated as unauthenticated."""
        resp = self.client.get("/api/v1/audit/logs", headers={"X-Reviewer-Id": ""})
        self.assertEqual(resp.status_code, 401)

    def test_authenticated_access_returns_records(self):
        """Valid X-Reviewer-Id returns audit records."""
        resp = self.client.get("/api/v1/audit/logs", headers={"X-Reviewer-Id": "admin-01"})
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)
        self.assertGreater(len(resp.json()), 0)

    def test_response_has_no_raw_parameters_redacted_field(self):
        """Audit records never expose parameters_redacted."""
        resp = self.client.get("/api/v1/audit/logs", headers={"X-Reviewer-Id": "admin-01"})
        for event in resp.json():
            self.assertNotIn("parameters_redacted", event)

    def test_verdict_filter_allow(self):
        """verdict=ALLOW filter returns only ALLOW records."""
        resp = self.client.get(
            "/api/v1/audit/logs?verdict=ALLOW", headers={"X-Reviewer-Id": "admin-01"}
        )
        self.assertEqual(resp.status_code, 200)
        for event in resp.json():
            self.assertEqual(event["verdict"], "ALLOW")

    def test_invalid_verdict_filter_returns_400(self):
        """Invalid verdict filter value returns 400."""
        resp = self.client.get(
            "/api/v1/audit/logs?verdict=GRANTED", headers={"X-Reviewer-Id": "admin-01"}
        )
        self.assertEqual(resp.status_code, 400)

    def test_limit_above_max_rejected_422(self):
        """limit > MAX_PAGE_SIZE returns 422."""
        resp = self.client.get(
            "/api/v1/audit/logs?limit=9999", headers={"X-Reviewer-Id": "admin-01"}
        )
        self.assertEqual(resp.status_code, 422)

    def test_negative_offset_rejected_422(self):
        """offset < 0 returns 422."""
        resp = self.client.get(
            "/api/v1/audit/logs?offset=-1", headers={"X-Reviewer-Id": "admin-01"}
        )
        self.assertEqual(resp.status_code, 422)


class TestAuthenticationBoundary(unittest.TestCase):
    """Ensure privileged endpoints reject unauthenticated callers."""

    def setUp(self):
        self.svc = _make_services()
        self.client = _make_client(self.svc)
        resp = self.client.post("/api/v1/intercept", json=REVIEW_BODY)
        self.ticket_id = resp.json().get("ticket_id")

    def test_review_decision_without_header_is_401(self):
        resp = self.client.post(
            f"/api/v1/reviews/{self.ticket_id}/decision",
            json={"decision": "APPROVED"},
        )
        self.assertEqual(resp.status_code, 401)

    def test_audit_logs_without_header_is_401(self):
        resp = self.client.get("/api/v1/audit/logs")
        self.assertEqual(resp.status_code, 401)

    def test_health_is_public_no_auth_needed(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)

    def test_intercept_is_public_no_auth_needed(self):
        resp = self.client.post(
            "/api/v1/intercept",
            json=_allow_body(request_id="req-public-noauth"),
        )
        self.assertEqual(resp.status_code, 200)

    def test_decision_lookup_is_public_no_auth_needed(self):
        # First create a decision
        self.client.post("/api/v1/intercept", json=_allow_body(request_id="req-pub-lookup"))
        resp = self.client.get("/api/v1/decisions/req-pub-lookup")
        self.assertEqual(resp.status_code, 200)


class TestCoreSecurityInvariants(unittest.TestCase):
    """End-to-end security guarantees that must hold unconditionally."""

    def setUp(self):
        self.client = _make_client()

    def test_block_verdict_always_has_allowed_false(self):
        data = self.client.post("/api/v1/intercept", json=BLOCK_BODY).json()
        self.assertEqual(data["verdict"], "BLOCK")
        self.assertFalse(data["allowed"])

    def test_review_verdict_always_has_allowed_false(self):
        data = self.client.post("/api/v1/intercept", json=REVIEW_BODY).json()
        self.assertEqual(data["verdict"], "REVIEW")
        self.assertFalse(data["allowed"])

    def test_allow_verdict_has_allowed_true(self):
        data = self.client.post(
            "/api/v1/intercept", json=_allow_body(request_id="req-inv-allow")
        ).json()
        self.assertEqual(data["verdict"], "ALLOW")
        self.assertTrue(data["allowed"])

    def test_risk_scores_always_bounded(self):
        """All intercept responses have risk_score in [0.0, 100.0]."""
        bodies = [
            _allow_body(request_id="req-bound-1"),
            dict(REVIEW_BODY, request_id="req-bound-2"),
            dict(BLOCK_BODY, request_id="req-bound-3"),
        ]
        for body in bodies:
            resp = self.client.post("/api/v1/intercept", json=body)
            if resp.status_code == 200:
                score = resp.json()["risk_score"]
                self.assertGreaterEqual(score, 0.0)
                self.assertLessEqual(score, 100.0)

    def test_error_responses_never_expose_tracebacks(self):
        """422 and 500 responses must not leak Python internals."""
        resp = self.client.post("/api/v1/intercept", json={"completely": "wrong"})
        self.assertNotIn("Traceback", resp.text)
        self.assertNotIn("raise ", resp.text)
        self.assertNotIn("File \"", resp.text)


if __name__ == "__main__":
    unittest.main()

import json
import unittest
import warnings
from datetime import datetime, timezone
from typing import Any, Collection, Dict, List, Optional
from unittest.mock import MagicMock, patch

# Suppress the httpx2 deprecation from starlette testclient (cosmetic only)
warnings.filterwarnings("ignore", category=DeprecationWarning, module="starlette")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="httpx")

from fastapi.testclient import TestClient

from zagentshield.anomalies.detector import AnomalyConfig, AnomalyDetector
from zagentshield.audit.logger import AuditLogger, AuditLoggingError
from zagentshield.core.enums import ActionCategory, ActionVerdict, RiskLevel
from zagentshield.core.models import AgentRequest, SecurityEvaluation
from zagentshield.db.database import Database
from zagentshield.db.repository import SecurityRepository
from zagentshield.policies.engine import PolicyConfig, PolicyEngine, PolicyRule


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def _make_memory_services(
    policy_data: Optional[Dict[str, Any]] = None,
    anomaly_detector: Optional[AnomalyDetector] = None,
    audit_logger_override=None,
    resource_classifier=_trusted_test_resource,
):
    """Build an isolated AppServices graph backed by an in-memory SQLite database."""
    from zagentshield.api.app import AppServices

    db = _SharedMemoryDatabase()
    repo = SecurityRepository(db)
    audit = audit_logger_override or AuditLogger(repo)

    if policy_data is None:
        policy_data = _default_policy_data()

    engine = PolicyEngine.from_dict(policy_data)
    detector = anomaly_detector or AnomalyDetector(config=AnomalyConfig(), repository=repo)

    return AppServices(
        policy_engine=engine,
        repository=repo,
        audit_logger=audit,
        anomaly_detector=detector,
        resource_classifier=resource_classifier,
    )


def _default_policy_data() -> Dict[str, Any]:
    return {
        "version": "1.0",
        "default_verdict": "BLOCK",
        "deny_rules": [
            {
                "rule_id": "deny-delete-all",
                "description": "Prohibit bulk delete operations",
                "applicable_action": "delete_all",
                "applicable_resource": "*",
                "category": "DELETE",
                "severity": "CRITICAL",
                "base_risk_score": 95.0,
            },
            {
                "rule_id": "deny-secrets",
                "description": "Prohibit access to secrets vault",
                "applicable_action": "*",
                "applicable_resource": "secrets/vault",
                "severity": "CRITICAL",
                "base_risk_score": 100.0,
            },
        ],
        "review_rules": [
            {
                "rule_id": "review-export",
                "description": "Bulk data export requires human review",
                "applicable_action": "export_data",
                "applicable_resource": "*",
                "category": "EXPORT",
                "severity": "HIGH",
                "base_risk_score": 60.0,
            },
        ],
        "allow_rules": [
            {
                "rule_id": "allow-read",
                "description": "Read operations on public resources are permitted",
                "applicable_action": "read_record",
                "applicable_resource": "public/*",
                "category": "READ",
                "severity": "LOW",
                "base_risk_score": 5.0,
            },
        ],
    }


def _valid_intercept_body(**overrides) -> Dict[str, Any]:
    """Construct a valid intercept request body."""
    base = {
        "agent_id": "agent-test-001",
        "action": "read_record",
        "category": "READ",
        "resource": "public/reports/q1",
        "parameters": {"format": "json"},
        "claimed_permissions": [],
        "context": {"session": "sess-abc"},
    }
    base.update(overrides)
    return base


REVIEW_BODY = {
    "agent_id": "agent-export-001",
    "action": "export_data",
    "category": "EXPORT",
    "resource": "reports/2024",
    "parameters": {},
}

BLOCK_BODY = {
    "agent_id": "agent-evil-001",
    "action": "delete_all",
    "category": "DELETE",
    "resource": "users/table",
    "parameters": {},
}


# ---------------------------------------------------------------------------
# Test Suite
# ---------------------------------------------------------------------------

class TestHealthEndpoint(unittest.TestCase):
    """GET /health"""

    def setUp(self):
        from zagentshield.api.app import create_app
        svc = _make_memory_services()
        self.client = TestClient(create_app(services=svc), raise_server_exceptions=False)

    def test_health_returns_200(self):
        """Health endpoint returns HTTP 200."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)

    def test_health_response_structure(self):
        """Health response has status, version, and timestamp."""
        resp = self.client.get("/health")
        data = resp.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("version", data)
        self.assertIn("timestamp", data)

    def test_health_does_not_expose_config_secrets(self):
        """Health response does not contain database_path, keys, or environment data."""
        resp = self.client.get("/health")
        body = resp.text
        self.assertNotIn("database_path", body)
        self.assertNotIn("policy_config_path", body)
        self.assertNotIn("secret", body.lower())


class TestInterceptEndpoint(unittest.TestCase):
    """POST /api/v1/intercept"""

    def setUp(self):
        from zagentshield.api.app import create_app
        self.svc = _make_memory_services()
        self.client = TestClient(create_app(services=self.svc), raise_server_exceptions=False)

    def test_valid_allow_request(self):
        """Valid read request against allow rule returns ALLOW verdict."""
        resp = self.client.post("/api/v1/intercept", json=_valid_intercept_body())
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["verdict"], "ALLOW")
        self.assertTrue(data["allowed"])
        self.assertFalse(data["review_required"])
        self.assertIsNone(data.get("ticket_id"))

    def test_valid_block_request(self):
        """Blocked action returns BLOCK verdict with allowed=False."""
        resp = self.client.post("/api/v1/intercept", json=BLOCK_BODY)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["verdict"], "BLOCK")
        self.assertFalse(data["allowed"])
        self.assertFalse(data["review_required"])

    def test_valid_review_request_returns_ticket(self):
        """REVIEW verdict returns allowed=False, review_required=True, and a ticket_id."""
        resp = self.client.post("/api/v1/intercept", json=REVIEW_BODY)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["verdict"], "REVIEW")
        self.assertFalse(data["allowed"])
        self.assertTrue(data["review_required"])
        self.assertIsNotNone(data.get("ticket_id"))
        self.assertTrue(data["ticket_id"].startswith("tkt-"))

    def test_review_ticket_lookup_failure_returns_error(self):
        """A REVIEW result is not successful if its required ticket cannot be read."""
        self.svc.repository.get_review_ticket_by_request_id = MagicMock(
            side_effect=RuntimeError("database unavailable")
        )

        resp = self.client.post("/api/v1/intercept", json=REVIEW_BODY)

        self.assertEqual(resp.status_code, 500)
        self.assertNotIn("database unavailable", resp.text)

    def test_invalid_schema_missing_required_fields(self):
        """Request missing required fields returns 422."""
        resp = self.client.post("/api/v1/intercept", json={"agent_id": "only-this"})
        self.assertEqual(resp.status_code, 422)

    def test_validation_error_does_not_echo_untrusted_input(self):
        """Pydantic validation messages must not reflect potentially sensitive values."""
        marker = "secret validation value!"
        body = _valid_intercept_body(agent_id=marker)
        resp = self.client.post("/api/v1/intercept", json=body)

        self.assertEqual(resp.status_code, 422)
        self.assertNotIn(marker, resp.text)

    def test_invalid_schema_extra_fields_rejected(self):
        """Request with extra unexpected fields returns 422 (extra='forbid')."""
        body = _valid_intercept_body()
        body["injected_admin_flag"] = True
        resp = self.client.post("/api/v1/intercept", json=body)
        self.assertEqual(resp.status_code, 422)

    def test_sensitive_parameters_not_echoed(self):
        """Response must not echo raw parameter values from the request."""
        body = _valid_intercept_body(
            parameters={"api_key": "super-secret-key-1234", "password": "hunter2"}
        )
        resp = self.client.post("/api/v1/intercept", json=body)
        self.assertEqual(resp.status_code, 200)
        body_text = resp.text
        self.assertNotIn("super-secret-key-1234", body_text)
        self.assertNotIn("hunter2", body_text)

    def test_block_verdict_has_no_allowed_flag(self):
        """BLOCK response always has allowed=False regardless of input claims."""
        body = BLOCK_BODY.copy()
        body["claimed_permissions"] = ["admin", "superuser", "root"]
        resp = self.client.post("/api/v1/intercept", json=body)
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["allowed"])

    def test_claimed_permissions_cannot_bypass_block(self):
        """Unverified claimed_permissions in request body cannot override BLOCK."""
        body = BLOCK_BODY.copy()
        body["claimed_permissions"] = ["allow_all", "bypass_security"]
        resp = self.client.post("/api/v1/intercept", json=body)
        data = resp.json()
        self.assertEqual(data["verdict"], "BLOCK")
        self.assertFalse(data["allowed"])

    def test_idempotency_duplicate_request_id(self):
        """Duplicate request_id returns the same verdict without re-evaluating."""
        body = _valid_intercept_body(request_id="req-dedup-001")
        resp1 = self.client.post("/api/v1/intercept", json=body)
        resp2 = self.client.post("/api/v1/intercept", json=body)
        self.assertEqual(resp1.status_code, 200)
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(resp1.json()["verdict"], resp2.json()["verdict"])

    def test_policy_engine_exception_fails_closed(self):
        """Policy engine exception results in 500 and never allows the action."""
        from zagentshield.api.app import create_app, AppServices

        broken_engine = MagicMock()
        broken_engine.evaluate.side_effect = RuntimeError("Policy rule evaluation failure")

        db = Database(":memory:")
        db.init_db()
        repo = SecurityRepository(db)
        svc = AppServices(
            policy_engine=broken_engine,
            repository=repo,
            audit_logger=AuditLogger(repo),
            anomaly_detector=None,
        )
        client = TestClient(create_app(services=svc), raise_server_exceptions=False)
        resp = client.post("/api/v1/intercept", json=_valid_intercept_body())
        self.assertEqual(resp.status_code, 500)
        # Must not claim success or ALLOW
        body_text = resp.text
        self.assertNotIn('"allowed": true', body_text)
        self.assertNotIn("ALLOW", body_text)

    def test_audit_failure_fails_closed(self):
        """Audit logging failure results in 500 and never grants ALLOW."""
        from zagentshield.api.app import create_app, AppServices

        broken_audit = MagicMock()
        broken_audit.log_evaluation.side_effect = AuditLoggingError("Disk full")

        db = Database(":memory:")
        db.init_db()
        repo = SecurityRepository(db)
        engine = PolicyEngine.from_dict(_default_policy_data())
        svc = AppServices(
            policy_engine=engine,
            repository=repo,
            audit_logger=broken_audit,
            anomaly_detector=None,
        )
        client = TestClient(create_app(services=svc), raise_server_exceptions=False)
        resp = client.post("/api/v1/intercept", json=_valid_intercept_body())
        self.assertEqual(resp.status_code, 500)
        self.assertNotIn("ALLOW", resp.text)

    def test_response_has_consistent_schema(self):
        """ALLOW response contains all required schema fields."""
        resp = self.client.post("/api/v1/intercept", json=_valid_intercept_body())
        data = resp.json()
        for field in ["request_id", "verdict", "allowed", "review_required",
                      "risk_score", "risk_level", "reasons", "matched_rule_ids",
                      "evaluated_at"]:
            self.assertIn(field, data, f"Missing field: {field}")

    def test_internal_exception_returns_500_not_stack_trace(self):
        """Unexpected exceptions return 500 without leaking stack traces."""
        from zagentshield.api.app import create_app, AppServices

        broken_engine = MagicMock()
        broken_engine.evaluate.side_effect = MemoryError("OOM")

        db = Database(":memory:")
        db.init_db()
        repo = SecurityRepository(db)
        svc = AppServices(
            policy_engine=broken_engine,
            repository=repo,
            audit_logger=AuditLogger(repo),
            anomaly_detector=None,
        )
        client = TestClient(create_app(services=svc), raise_server_exceptions=False)
        resp = client.post("/api/v1/intercept", json=_valid_intercept_body())
        self.assertEqual(resp.status_code, 500)
        body_text = resp.text
        self.assertNotIn("Traceback", body_text)
        self.assertNotIn("MemoryError", body_text)


class TestDecisionLookupEndpoint(unittest.TestCase):
    """GET /api/v1/decisions/{request_id}"""

    def setUp(self):
        from zagentshield.api.app import create_app
        self.svc = _make_memory_services()
        self.client = TestClient(create_app(services=self.svc), raise_server_exceptions=False)

    def _create_decision(self, request_id: str) -> None:
        body = _valid_intercept_body(request_id=request_id)
        self.client.post("/api/v1/intercept", json=body)

    def test_decision_lookup_success(self):
        """Recorded decision is retrievable by request_id."""
        self._create_decision("req-lookup-001")
        resp = self.client.get("/api/v1/decisions/req-lookup-001")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["request_id"], "req-lookup-001")
        self.assertIn("verdict", data)

    def test_decision_lookup_not_found(self):
        """Non-existent request_id returns 404."""
        resp = self.client.get("/api/v1/decisions/req-does-not-exist")
        self.assertEqual(resp.status_code, 404)

    def test_decision_response_has_no_raw_parameters(self):
        """Decision lookup response does not include raw parameters."""
        self._create_decision("req-param-check-001")
        resp = self.client.get("/api/v1/decisions/req-param-check-001")
        data = resp.json()
        self.assertNotIn("parameters", data)
        self.assertNotIn("parameters_redacted", data)

    def test_decision_response_schema(self):
        """Decision response has correct fields."""
        self._create_decision("req-schema-001")
        resp = self.client.get("/api/v1/decisions/req-schema-001")
        data = resp.json()
        for field in ["id", "request_id", "agent_id", "action", "verdict",
                      "risk_score", "risk_level", "reasons", "timestamp"]:
            self.assertIn(field, data, f"Missing field: {field}")


class TestReviewListEndpoint(unittest.TestCase):
    """GET /api/v1/reviews"""

    def setUp(self):
        from zagentshield.api.app import create_app
        self.svc = _make_memory_services()
        self.client = TestClient(create_app(services=self.svc), raise_server_exceptions=False)

    def _create_review_ticket(self) -> str:
        resp = self.client.post("/api/v1/intercept", json=REVIEW_BODY)
        return resp.json().get("ticket_id", "")

    def test_reviews_list_returns_pending(self):
        """Review list returns pending tickets."""
        self._create_review_ticket()
        resp = self.client.get("/api/v1/reviews")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)

    def test_reviews_list_empty_when_no_pending(self):
        """Review list is empty when there are no pending tickets."""
        resp = self.client.get("/api/v1/reviews")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])

    def test_reviews_pagination_limit_respected(self):
        """Pagination limit parameter is respected."""
        # Create 3 review tickets with distinct request_ids
        for i in range(3):
            body = REVIEW_BODY.copy()
            body["request_id"] = f"req-pagination-{i:03d}"
            self.client.post("/api/v1/intercept", json=body)

        resp = self.client.get("/api/v1/reviews?limit=2")
        self.assertEqual(resp.status_code, 200)
        self.assertLessEqual(len(resp.json()), 2)

    def test_reviews_pagination_limit_max_bounded(self):
        """Limit above MAX_PAGE_SIZE is rejected."""
        resp = self.client.get("/api/v1/reviews?limit=9999")
        self.assertEqual(resp.status_code, 422)

    def test_reviews_ticket_schema(self):
        """Review ticket response has all required fields."""
        self._create_review_ticket()
        resp = self.client.get("/api/v1/reviews")
        ticket = resp.json()[0]
        for field in ["ticket_id", "request_id", "agent_id", "action",
                      "status", "risk_score", "risk_level", "reasons",
                      "created_at", "updated_at"]:
            self.assertIn(field, ticket, f"Missing field: {field}")


class TestReviewDecisionEndpoint(unittest.TestCase):
    """POST /api/v1/reviews/{ticket_id}/decision"""

    def setUp(self):
        from zagentshield.api.app import create_app
        self.svc = _make_memory_services()
        self.client = TestClient(create_app(services=self.svc), raise_server_exceptions=False)
        # Create one review ticket upfront
        resp = self.client.post("/api/v1/intercept", json=REVIEW_BODY)
        self.ticket_id = resp.json().get("ticket_id")

    def _decide(self, ticket_id: str, decision: str, reviewer_id: str = "reviewer-alice",
                notes: Optional[str] = None):
        body = {"decision": decision}
        if notes:
            body["reviewer_notes"] = notes
        return self.client.post(
            f"/api/v1/reviews/{ticket_id}/decision",
            json=body,
            headers={"X-Reviewer-Id": reviewer_id},
        )

    def test_approve_review_ticket(self):
        """Valid APPROVED decision updates the ticket status."""
        resp = self._decide(self.ticket_id, "APPROVED", notes="Manually reviewed.")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "APPROVED")
        self.assertEqual(data["reviewer_id"], "reviewer-alice")

    def test_reject_review_ticket(self):
        """Valid REJECTED decision updates the ticket status."""
        resp = self._decide(self.ticket_id, "REJECTED")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "REJECTED")

    def test_unauthenticated_request_denied(self):
        """Missing X-Reviewer-Id header returns 401."""
        resp = self.client.post(
            f"/api/v1/reviews/{self.ticket_id}/decision",
            json={"decision": "APPROVED"},
        )
        self.assertEqual(resp.status_code, 401)

    def test_client_supplied_reviewer_id_in_body_is_ignored(self):
        """reviewer_id in the JSON body has no effect; only the header is trusted."""
        # We supply a fake reviewer in the body — it should be ignored
        resp = self.client.post(
            f"/api/v1/reviews/{self.ticket_id}/decision",
            json={"decision": "APPROVED", "fake_reviewer": "attacker-id"},
            headers={"X-Reviewer-Id": "reviewer-bob"},
        )
        self.assertEqual(resp.status_code, 422)  # 'fake_reviewer' is extra field → 422
        # Or if extra field is not in model, verify ticket is not corrupted
        ticket = self.svc.repository.get_review_ticket(self.ticket_id)
        # ticket should still be PENDING since the request was rejected
        self.assertEqual(ticket.status, "PENDING")

    def test_invalid_decision_value_rejected(self):
        """Invalid decision value returns 400."""
        resp = self._decide(self.ticket_id, "MAYBE")
        self.assertEqual(resp.status_code, 400)

    def test_double_decision_conflict(self):
        """Re-deciding an already terminal ticket returns 409."""
        self._decide(self.ticket_id, "APPROVED")
        resp = self._decide(self.ticket_id, "REJECTED")
        self.assertEqual(resp.status_code, 409)

    def test_nonexistent_ticket_returns_404(self):
        """Decision on a non-existent ticket returns 404."""
        resp = self._decide("tkt-does-not-exist", "APPROVED")
        self.assertEqual(resp.status_code, 404)

    def test_approve_does_not_auto_execute(self):
        """Approving a ticket must NOT automatically execute any operation."""
        # The response just confirms status change; no execution_result or callback
        resp = self._decide(self.ticket_id, "APPROVED")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertNotIn("execution_result", data)
        # Status is APPROVED but nothing executed
        self.assertEqual(data["status"], "APPROVED")


class TestAuditLogsEndpoint(unittest.TestCase):
    """GET /api/v1/audit/logs"""

    def setUp(self):
        from zagentshield.api.app import create_app
        self.svc = _make_memory_services()
        self.client = TestClient(create_app(services=self.svc), raise_server_exceptions=False)
        # Seed one decision
        self.client.post("/api/v1/intercept", json=_valid_intercept_body())

    def test_unauthenticated_audit_access_denied(self):
        """Missing X-Reviewer-Id returns 401."""
        resp = self.client.get("/api/v1/audit/logs")
        self.assertEqual(resp.status_code, 401)

    def test_authenticated_audit_access_succeeds(self):
        """Valid X-Reviewer-Id header allows audit log access."""
        resp = self.client.get(
            "/api/v1/audit/logs",
            headers={"X-Reviewer-Id": "admin-charlie"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)
        self.assertGreater(len(resp.json()), 0)

    def test_audit_response_has_no_raw_parameters(self):
        """Audit records do not expose raw parameters_redacted field."""
        resp = self.client.get(
            "/api/v1/audit/logs",
            headers={"X-Reviewer-Id": "admin-charlie"},
        )
        for event in resp.json():
            self.assertNotIn("parameters_redacted", event)

    def test_audit_verdict_filter_valid(self):
        """Valid verdict filter returns correct results."""
        resp = self.client.get(
            "/api/v1/audit/logs?verdict=ALLOW",
            headers={"X-Reviewer-Id": "admin-charlie"},
        )
        self.assertEqual(resp.status_code, 200)
        for event in resp.json():
            self.assertEqual(event["verdict"], "ALLOW")

    def test_audit_verdict_filter_invalid(self):
        """Invalid verdict filter returns 400."""
        resp = self.client.get(
            "/api/v1/audit/logs?verdict=GRANTED",
            headers={"X-Reviewer-Id": "admin-charlie"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_audit_pagination_limit_max_bounded(self):
        """Limit above MAX_PAGE_SIZE is rejected with 422."""
        resp = self.client.get(
            "/api/v1/audit/logs?limit=9999",
            headers={"X-Reviewer-Id": "admin-charlie"},
        )
        self.assertEqual(resp.status_code, 422)

    def test_audit_pagination_offset_negative_rejected(self):
        """Negative offset is rejected with 422."""
        resp = self.client.get(
            "/api/v1/audit/logs?offset=-1",
            headers={"X-Reviewer-Id": "admin-charlie"},
        )
        self.assertEqual(resp.status_code, 422)


class TestAuthenticationBoundary(unittest.TestCase):
    """Authentication boundary enforcement across privileged endpoints."""

    def setUp(self):
        from zagentshield.api.app import create_app
        self.svc = _make_memory_services()
        self.client = TestClient(create_app(services=self.svc), raise_server_exceptions=False)
        # Create a ticket for review endpoints
        resp = self.client.post("/api/v1/intercept", json=REVIEW_BODY)
        self.ticket_id = resp.json().get("ticket_id")

    def test_review_decision_without_header_returns_401(self):
        """Review decision endpoint requires X-Reviewer-Id header."""
        resp = self.client.post(
            f"/api/v1/reviews/{self.ticket_id}/decision",
            json={"decision": "APPROVED"},
        )
        self.assertEqual(resp.status_code, 401)

    def test_audit_logs_without_header_returns_401(self):
        """Audit logs endpoint requires X-Reviewer-Id header."""
        resp = self.client.get("/api/v1/audit/logs")
        self.assertEqual(resp.status_code, 401)

    def test_empty_reviewer_id_header_returns_401(self):
        """Empty X-Reviewer-Id header is treated as unauthenticated."""
        resp = self.client.get(
            "/api/v1/audit/logs",
            headers={"X-Reviewer-Id": ""},
        )
        self.assertEqual(resp.status_code, 401)

    def test_intercept_is_public_no_header_required(self):
        """Intercept endpoint is not a privileged endpoint and requires no auth header."""
        resp = self.client.post("/api/v1/intercept", json=_valid_intercept_body(
            request_id="req-public-001"
        ))
        self.assertEqual(resp.status_code, 200)

    def test_health_is_public(self):
        """Health endpoint is public."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)


class TestGatewaySecurityInvariants(unittest.TestCase):
    """Core security invariants that must hold across all conditions."""

    def setUp(self):
        from zagentshield.api.app import create_app
        self.svc = _make_memory_services()
        self.client = TestClient(create_app(services=self.svc), raise_server_exceptions=False)

    def test_block_verdict_always_has_allowed_false(self):
        """Regardless of input, BLOCK verdict must have allowed=False."""
        resp = self.client.post("/api/v1/intercept", json=BLOCK_BODY)
        self.assertEqual(resp.json()["verdict"], "BLOCK")
        self.assertFalse(resp.json()["allowed"])

    def test_review_verdict_never_has_allowed_true(self):
        """REVIEW verdict must never have allowed=True."""
        resp = self.client.post("/api/v1/intercept", json=REVIEW_BODY)
        self.assertEqual(resp.json()["verdict"], "REVIEW")
        self.assertFalse(resp.json()["allowed"])

    def test_allow_verdict_has_allowed_true(self):
        """ALLOW verdict has allowed=True."""
        resp = self.client.post("/api/v1/intercept", json=_valid_intercept_body())
        self.assertEqual(resp.json()["verdict"], "ALLOW")
        self.assertTrue(resp.json()["allowed"])

    def test_mandatory_deny_rule_cannot_be_bypassed(self):
        """Mandatory deny rule (secrets/vault) blocks even with claimed permissions."""
        body = {
            "agent_id": "agent-try-bypass",
            "action": "read_secret",
            "category": "READ",
            "resource": "secrets/vault",
            "claimed_permissions": ["admin", "read_secrets", "bypass"],
        }
        resp = self.client.post("/api/v1/intercept", json=body)
        self.assertEqual(resp.json()["verdict"], "BLOCK")
        self.assertFalse(resp.json()["allowed"])

    def test_risk_score_always_in_valid_range(self):
        """All intercept responses have risk_score in [0.0, 100.0]."""
        for body in [_valid_intercept_body(request_id="req-rs-1"), REVIEW_BODY, BLOCK_BODY]:
            resp = self.client.post("/api/v1/intercept", json=body)
            if resp.status_code == 200:
                score = resp.json()["risk_score"]
                self.assertGreaterEqual(score, 0.0)
                self.assertLessEqual(score, 100.0)

    def test_error_responses_never_expose_stack_traces(self):
        """Error responses must not leak Python exception details."""
        # Send malformed request to trigger validation error
        resp = self.client.post("/api/v1/intercept", json={"bad": "input"})
        self.assertNotIn("Traceback", resp.text)
        self.assertNotIn("raise ", resp.text)

    def test_module_exports_uvicorn_application(self):
        """The documented Uvicorn import path must expose an ASGI application."""
        from zagentshield.api.app import app

        paths = {route.path for route in app.routes}
        self.assertIn("/health", paths)
        self.assertIn("/api/v1/intercept", paths)


if __name__ == "__main__":
    unittest.main()
