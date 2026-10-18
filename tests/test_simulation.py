"""Tests for synthetic scenarios evaluated through the actual gateway."""

import unittest

from fastapi.testclient import TestClient

from zagentshield.api.app import create_app
from zagentshield.simulation import SCENARIOS, build_simulation_request
from tests.test_api import _make_memory_services


class TestAttackSimulations(unittest.TestCase):
    def test_scenarios_are_synthetic_and_unique(self):
        requests = [build_simulation_request(scenario) for scenario in SCENARIOS]
        self.assertEqual(len({request["request_id"] for request in requests}), len(SCENARIOS))
        for request in requests:
            self.assertEqual(request["agent_id"], "synthetic-simulator")
            self.assertEqual(request["parameters"]["simulation"], "synthetic")
            self.assertTrue(request["resource"].startswith("synthetic://"))
            self.assertEqual(request["claimed_permissions"], [])

    def test_each_scenario_is_processed_by_gateway_policy(self):
        services = _make_memory_services()
        client = TestClient(create_app(services=services))
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario):
                body = build_simulation_request(scenario)
                response = client.post("/api/v1/intercept", json=body)
                self.assertEqual(response.status_code, 200)
                result = response.json()
                self.assertIn(result["verdict"], {"ALLOW", "REVIEW", "BLOCK"})
                self.assertEqual(result["allowed"], result["verdict"] == "ALLOW")
                self.assertEqual(result["review_required"], result["verdict"] == "REVIEW")
        self.assertEqual(services.repository.count_security_events(), len(SCENARIOS))

    def test_unknown_scenario_fails_explicitly(self):
        with self.assertRaises(ValueError):
            build_simulation_request("real_customer_attack")


if __name__ == "__main__":
    unittest.main()
