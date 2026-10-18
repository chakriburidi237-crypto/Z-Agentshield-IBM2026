"""Tests for local RBAC authentication and signed session tokens."""

import json
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from zagentshield.audit.redaction import redact_sensitive_data
from zagentshield.auth import (
    AuthenticatedUser,
    AuthenticationError,
    AuthenticationUnavailable,
    LocalAuthManager,
    create_password_record,
)
from zagentshield.api.app import create_app
from tests.test_api import _make_memory_services


class TestLocalAuthManager(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        password_record = create_password_record("valid-demo-password-01")
        cls.users = json.dumps(
            [
                {
                    "username": "analyst",
                    "role": "SOC_ANALYST",
                    **password_record,
                }
            ]
        )

    def manager(self):
        return LocalAuthManager(self.users, "t" * 40)

    def test_login_issues_signed_role_token(self):
        manager = self.manager()
        token, user = manager.login("analyst", "valid-demo-password-01")
        self.assertEqual(user, AuthenticatedUser("analyst", "SOC_ANALYST"))
        self.assertEqual(manager.verify_token(token), user)

    def test_invalid_password_fails(self):
        with self.assertRaises(AuthenticationError):
            self.manager().login("analyst", "incorrect-password")

    def test_token_tampering_fails(self):
        manager = self.manager()
        token, _ = manager.login("analyst", "valid-demo-password-01")
        with self.assertRaises(AuthenticationError):
            manager.verify_token(token + "tampered")

    def test_expired_token_fails(self):
        manager = self.manager()
        with patch.object(time, "time", return_value=100):
            token, _ = manager.login("analyst", "valid-demo-password-01")
        with patch.object(time, "time", return_value=100 + 901):
            with self.assertRaises(AuthenticationError):
                manager.verify_token(token)

    def test_configured_token_lifetime_is_used(self):
        manager = LocalAuthManager(self.users, "t" * 40, token_lifetime_seconds=120)
        with patch.object(time, "time", return_value=100):
            token, _ = manager.login("analyst", "valid-demo-password-01")
        with patch.object(time, "time", return_value=220):
            with self.assertRaises(AuthenticationError):
                manager.verify_token(token)

    def test_token_lifetime_is_bounded(self):
        with self.assertRaises(ValueError):
            LocalAuthManager(self.users, "t" * 40, token_lifetime_seconds=10)

    def test_missing_auth_configuration_is_unavailable(self):
        manager = LocalAuthManager("", "")
        with self.assertRaises(AuthenticationUnavailable):
            manager.login("analyst", "password")

    def test_client_cannot_assign_privileged_role(self):
        with self.assertRaises(ValueError):
            LocalAuthManager(
                json.dumps(
                    [
                        {
                            "username": "attacker",
                            "role": "ROOT",
                            **create_password_record("valid-demo-password-02"),
                        }
                    ]
                ),
                "t" * 40,
            )

    def test_login_and_reviewer_decision_use_authenticated_identity(self):
        services = _make_memory_services()
        services.auth_manager = self.manager()
        client = TestClient(create_app(services=services))
        services.repository.create_review_ticket(
            request_id="req-auth-review",
            agent_id="synthetic-agent",
            action="export",
            category="EXPORT",
            resource="synthetic/data",
            risk_score=60,
            risk_level="HIGH",
            reasons=["Synthetic authorization test"],
        )
        ticket = services.repository.get_review_ticket_by_request_id("req-auth-review")

        login = client.post(
            "/api/v1/auth/login",
            json={"username": "analyst", "password": "valid-demo-password-01"},
        )
        self.assertEqual(login.status_code, 200)
        token = login.json()["access_token"]
        raw_notes = "Bearer abcdefghijklmnopqrstuvwxyz"
        sanitized_notes = redact_sensitive_data(raw_notes)
        decided = client.post(
            f"/api/v1/reviews/{ticket.ticket_id}/decision",
            headers={"Authorization": f"Bearer {token}", "X-Reviewer-Id": "forged-admin"},
            json={
                "decision": "REJECTED",
                "reviewer_notes": raw_notes,
            },
        )
        self.assertEqual(decided.status_code, 200)
        self.assertEqual(decided.json()["reviewer_id"], "analyst")
        self.assertEqual(decided.json()["reviewer_notes"], sanitized_notes)
        persisted_ticket = services.repository.get_review_ticket(ticket.ticket_id)
        self.assertEqual(persisted_ticket.reviewer_notes, sanitized_notes)
        chain = services.repository.verify_audit_chain()
        self.assertTrue(chain["valid"])
        self.assertEqual(chain["entries_checked"], 1)

    def test_identity_header_alone_cannot_access_reviews(self):
        services = _make_memory_services()
        services.auth_manager = self.manager()
        client = TestClient(create_app(services=services))
        response = client.get(
            "/api/v1/reviews", headers={"X-Reviewer-Id": "attacker-admin"}
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
