"""Verify a running local Z-AgentShield API and Streamlit dashboard."""

from pathlib import Path
import os
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:
    import requests
except ImportError:
    print("[ERROR] The selected Python environment does not have requests installed.")
    print("Install project dependencies with: python -m pip install -r requirements.txt")
    raise SystemExit(1)

from zagentshield.config import get_settings
from zagentshield.core.schemas import InterceptRequest
from zagentshield.policies.engine import PolicyEngine

GATEWAY_URL = os.getenv("ZAGENTSHIELD_GATEWAY_URL", "http://127.0.0.1:8000")
DASHBOARD_URL = os.getenv("ZAGENTSHIELD_DASHBOARD_URL", "http://127.0.0.1:8501")
TEST_REVIEWER_ID = "local-verification-reviewer"
VALID_VERDICTS = {"ALLOW", "REVIEW", "BLOCK"}


class Verification:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.gateway_url = GATEWAY_URL
        self.dashboard_url = DASHBOARD_URL
        self.request_ids: list[str] = []
        self.ticket_id: str | None = None
        self.secret_marker = f"ZASHIELD-VERIFY-SECRET-{uuid.uuid4().hex}"

    def check(self, name: str, passed: bool, detail: str) -> None:
        if passed:
            self.passed += 1
            print(f"[PASS] {name}: {detail}")
        else:
            self.failed += 1
            print(f"[FAIL] {name}: {detail}")

    def request(self, name: str, method: str, url: str, **kwargs):
        try:
            return requests.request(method, url, timeout=5, **kwargs)
        except requests.RequestException as exc:
            self.check(name, False, f"request failed: {exc}")
            return None

    @staticmethod
    def response_json(response):
        try:
            return response.json()
        except (ValueError, requests.JSONDecodeError):
            return None

    def configured_verdict(self, body: dict) -> str | None:
        try:
            settings = get_settings()
            policy_path = Path(settings.policy_config_path)
            if not policy_path.is_absolute():
                policy_path = ROOT / policy_path
            engine = PolicyEngine.from_yaml_file(
                str(policy_path),
                risk_threshold_review=settings.risk_threshold_review,
                risk_threshold_block=settings.risk_threshold_block,
            )
            request = InterceptRequest.model_validate(body).to_agent_request()
            verdict = engine.evaluate(
                request=request,
                trusted_permissions=None,
                anomaly_assessment=None,
            ).verdict.value
            return verdict
        except Exception as exc:
            print(f"[WARN] Could not calculate configured policy baseline: {exc}")
            return None

    def test_api_availability(self) -> None:
        print("\n--- A. API availability ---")
        response = self.request("GET /", "GET", f"{self.gateway_url}/")
        if response is not None:
            data = self.response_json(response)
            self.check(
                "GET /",
                response.status_code == 200
                and isinstance(data, dict)
                and data.get("service") == "Z-AgentShield Security Gateway"
                and bool(data.get("version")),
                f"HTTP {response.status_code}; service={getattr(data, 'get', lambda *_: None)('service')}, "
                f"version={getattr(data, 'get', lambda *_: None)('version')}",
            )

        response = self.request("GET /health", "GET", f"{self.gateway_url}/health")
        if response is not None:
            data = self.response_json(response)
            self.check(
                "GET /health",
                response.status_code == 200
                and isinstance(data, dict)
                and data.get("status") == "ok"
                and bool(data.get("version"))
                and bool(data.get("timestamp")),
                f"HTTP {response.status_code}; status="
                f"{getattr(data, 'get', lambda *_: None)('status')}, "
                f"version={getattr(data, 'get', lambda *_: None)('version')}",
            )

    def test_swagger_and_openapi(self) -> None:
        print("\n--- B-C. Swagger UI and OpenAPI ---")
        response = self.request("GET /docs", "GET", f"{self.gateway_url}/docs")
        if response is not None:
            self.check(
                "GET /docs",
                response.status_code == 200 and "swagger-ui" in response.text.lower(),
                f"HTTP {response.status_code}",
            )

        response = self.request(
            "GET /openapi.json", "GET", f"{self.gateway_url}/openapi.json"
        )
        if response is not None:
            schema = self.response_json(response)
            expected_paths = {
                "/",
                "/health",
                "/api/v1/intercept",
                "/api/v1/decisions/{request_id}",
                "/api/v1/reviews",
                "/api/v1/reviews/{ticket_id}/decision",
                "/api/v1/audit/logs",
            }
            actual_paths = set(schema.get("paths", {})) if isinstance(schema, dict) else set()
            missing = sorted(expected_paths - actual_paths)
            self.check(
                "GET /openapi.json",
                response.status_code == 200 and schema is not None and not missing,
                f"HTTP {response.status_code}; documented paths={len(actual_paths)}; "
                f"missing={missing}",
            )

    def verify_intercept(self, label: str, body: dict) -> dict | None:
        expected = self.configured_verdict(body)
        response = self.request(
            f"POST /api/v1/intercept ({label})",
            "POST",
            f"{self.gateway_url}/api/v1/intercept",
            json=body,
        )
        if response is None:
            return None
        data = self.response_json(response)
        verdict = data.get("verdict") if isinstance(data, dict) else None
        valid_shape = (
            response.status_code == 200
            and verdict in VALID_VERDICTS
            and data.get("request_id") == body["request_id"]
            and data.get("allowed") is (verdict == "ALLOW")
            and data.get("review_required") is (verdict == "REVIEW")
        )
        if expected is not None:
            valid_shape = valid_shape and verdict == expected
        if label == "Bulk export" and expected == "REVIEW":
            valid_shape = valid_shape and verdict == "REVIEW"
        self.check(
            f"POST /api/v1/intercept ({label})",
            valid_shape,
            f"HTTP {response.status_code}; returned verdict={verdict}; "
            f"configured policy baseline={expected or 'unavailable'}",
        )
        if response.status_code == 200 and isinstance(data, dict):
            if body["request_id"] not in self.request_ids:
                self.request_ids.append(body["request_id"])
            if verdict == "REVIEW":
                ticket_id = data.get("ticket_id")
                if isinstance(ticket_id, str) and ticket_id:
                    self.ticket_id = ticket_id
                else:
                    self.check(
                        f"{label} review ticket",
                        False,
                        "REVIEW response did not include a ticket_id",
                    )
        self.check(
            f"{label} response redaction",
            self.secret_marker not in response.text,
            "synthetic secret marker was not returned",
        )
        return data if isinstance(data, dict) else None

    def test_intercept_decisions_and_reviews(self) -> None:
        print("\n--- D-E. Interception, decision lookup, and review queue ---")
        allow_id = f"req-verify-{uuid.uuid4().hex}"
        allow_body = {
            "request_id": allow_id,
            "agent_id": f"agent-verify-{uuid.uuid4().hex[:8]}",
            "action": "read_faq",
            "category": "READ",
            "resource": "public/faq/verification",
            "parameters": {
                "query": "synthetic local verification",
                "api_key": self.secret_marker,
            },
        }
        allow_result = self.verify_intercept("Public FAQ read", allow_body)

        if allow_result is not None:
            duplicate = self.request(
                "Repeated request id",
                "POST",
                f"{self.gateway_url}/api/v1/intercept",
                json=allow_body,
            )
            if duplicate is not None:
                duplicate_data = self.response_json(duplicate)
                self.check(
                    "Repeated request id",
                    duplicate.status_code == 200
                    and isinstance(duplicate_data, dict)
                    and duplicate_data.get("request_id") == allow_id
                    and duplicate_data.get("verdict") == allow_result.get("verdict"),
                    "same request returns its existing decision",
                )

        bulk_id = f"req-verify-{uuid.uuid4().hex}"
        bulk_body = {
            "request_id": bulk_id,
            "agent_id": f"agent-verify-{uuid.uuid4().hex[:8]}",
            "action": "bulk_export_verification",
            "category": "EXPORT",
            "resource": "data://synthetic/verification",
            "parameters": {
                "record_count": 3,
                "api_key": self.secret_marker,
            },
        }
        bulk_result = self.verify_intercept("Bulk export demonstration", bulk_body)

        for request_id in self.request_ids:
            response = self.request(
                f"Decision lookup {request_id}",
                "GET",
                f"{self.gateway_url}/api/v1/decisions/{request_id}",
            )
            if response is not None:
                data = self.response_json(response)
                self.check(
                    f"Decision lookup {request_id}",
                    response.status_code == 200
                    and isinstance(data, dict)
                    and data.get("request_id") == request_id,
                    f"HTTP {response.status_code}; recorded verdict="
                    f"{data.get('verdict') if isinstance(data, dict) else 'invalid response'}",
                )

        response = self.request(
            "GET pending reviews",
            "GET",
            f"{self.gateway_url}/api/v1/reviews?limit=50",
        )
        if response is not None:
            tickets = self.response_json(response)
            well_formed = response.status_code == 200 and isinstance(tickets, list)
            ticket_found = (
                self.ticket_id is None
                or (
                    well_formed
                    and any(
                        isinstance(ticket, dict)
                        and ticket.get("ticket_id") == self.ticket_id
                        and ticket.get("status") == "PENDING"
                        for ticket in tickets
                    )
                )
            )
            self.check(
                "GET pending reviews",
                well_formed and ticket_found,
                f"HTTP {response.status_code}; matching synthetic pending ticket="
                f"{self.ticket_id is not None and ticket_found}",
            )

        if self.ticket_id:
            response = self.request(
                "Review authorization boundary",
                "POST",
                f"{self.gateway_url}/api/v1/reviews/{self.ticket_id}/decision",
                json={"decision": "APPROVED"},
            )
            if response is not None:
                self.check(
                    "Review authorization boundary",
                    response.status_code == 401,
                    f"unauthenticated decision request returned HTTP {response.status_code}; "
                    "ticket was not approved",
                )
        else:
            print(
                "[INFO] The current configured policy did not create a REVIEW ticket; "
                "no approval/rejection request was sent."
            )

    def test_audit(self) -> None:
        print("\n--- F. Audit authorization and sanitization ---")
        response = self.request(
            "Unauthenticated audit access",
            "GET",
            f"{self.gateway_url}/api/v1/audit/logs?limit=200",
        )
        if response is not None:
            self.check(
                "Unauthenticated audit access",
                response.status_code == 401,
                f"HTTP {response.status_code}",
            )

        response = self.request(
            "Authenticated audit access",
            "GET",
            f"{self.gateway_url}/api/v1/audit/logs?limit=200",
            headers={"X-Reviewer-Id": TEST_REVIEWER_ID},
        )
        if response is not None:
            events = self.response_json(response)
            well_formed = response.status_code == 200 and isinstance(events, list)
            event_ids = {
                event.get("request_id")
                for event in events or []
                if isinstance(event, dict)
            }
            found_requests = set(self.request_ids).issubset(event_ids)
            sanitized = (
                isinstance(events, list)
                and all(
                    "parameters_redacted" not in event
                    for event in events
                    if isinstance(event, dict)
                )
                and self.secret_marker not in response.text
            )
            self.check(
                "Authenticated audit access and sanitization",
                well_formed and found_requests and sanitized,
                f"HTTP {response.status_code}; synthetic events found={found_requests}; "
                f"secret marker exposed={self.secret_marker in response.text}",
            )
            print(
                "[INFO] X-Reviewer-Id is a local integration header in this project, "
                "not cryptographic authentication. Do not expose this gateway to untrusted clients."
            )

    def test_dashboard(self) -> None:
        print("\n--- G. Streamlit dashboard ---")
        health = self.request(
            "Dashboard gateway dependency",
            "GET",
            f"{self.gateway_url}/health",
        )
        gateway_healthy = (
            health is not None
            and health.status_code == 200
            and isinstance(self.response_json(health), dict)
            and self.response_json(health).get("status") == "ok"
        )
        response = self.request(
            "Dashboard HTTP endpoint",
            "GET",
            self.dashboard_url,
        )
        if response is not None:
            self.check(
                "Dashboard HTTP endpoint",
                response.status_code == 200
                and "text/html" in response.headers.get("content-type", "").lower(),
                f"HTTP {response.status_code}; dashboard URL={self.dashboard_url}",
            )

        response = self.request(
            "Streamlit health endpoint",
            "GET",
            f"{self.dashboard_url}/_stcore/health",
        )
        if response is not None:
            self.check(
                "Streamlit health endpoint",
                response.status_code == 200,
                f"HTTP {response.status_code}",
            )
        self.check(
            "Dashboard gateway dependency",
            gateway_healthy,
            f"gateway health is available at {self.gateway_url}/health; "
            "inspect the dashboard sidebar to visually confirm its ONLINE status",
        )
        print(f"[INFO] Manual visual inspection: {self.dashboard_url}")
        print("[INFO] HTTP health checks do not constitute visual verification.")

    def run(self) -> int:
        print("=" * 72)
        print("Z-AgentShield live local verification")
        print(f"Gateway:   {self.gateway_url}")
        print(f"Dashboard: {self.dashboard_url}")
        print(
            "[INFO] Uses synthetic request IDs and a synthetic secret marker. "
            "It never approves or rejects a review ticket."
        )
        marker = ROOT / "scripts" / ".local_db_path"
        if marker.exists():
            print("[INFO] Runner database marker found; test events use the isolated local-run database.")
        else:
            print(
                "[WARN] No runner database marker found. Interception tests will create "
                "synthetic audit records in the API's configured database."
            )
        print("=" * 72)

        self.test_api_availability()
        self.test_swagger_and_openapi()
        self.test_intercept_decisions_and_reviews()
        self.test_audit()
        self.test_dashboard()
        print("\n" + "=" * 72)
        print(f"RESULT: {self.passed} passed, {self.failed} failed")
        print(
            "State change: up to two synthetic audit events and, if policy returns REVIEW, "
            "one synthetic pending review ticket. No ticket is approved or rejected."
        )
        print("=" * 72)
        return 1 if self.failed else 0


if __name__ == "__main__":
    raise SystemExit(Verification().run())
