"""Smoke tests for dashboard rendering and non-persistent policy previews."""

import os
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import streamlit as st
from streamlit.testing.v1 import AppTest

from zagentshield.config import get_settings
from zagentshield.db.database import Database
from zagentshield.db.repository import SecurityRepository


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_PATH = ROOT / "dashboard" / "app.py"


class TestDashboard(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "dashboard-test.db"
        self.environment = patch.dict(
            os.environ,
            {
                "DATABASE_PATH": str(self.database_path),
                "POLICY_CONFIG_PATH": str(ROOT / "config" / "policies.yaml"),
                "PORT": "9",
            },
        )
        self.environment.start()
        get_settings.cache_clear()
        st.cache_resource.clear()

        self.database = Database(self.database_path)
        self.database.init_db()
        self.repository = SecurityRepository(self.database)

    def tearDown(self) -> None:
        st.cache_resource.clear()
        get_settings.cache_clear()
        self.environment.stop()
        self.temp_dir.cleanup()

    def render_dashboard(self):
        return AppTest.from_file(str(DASHBOARD_PATH), default_timeout=60).run()

    def test_all_dashboard_sections_render_with_empty_data(self) -> None:
        app = self.render_dashboard()
        expected_sections = {
            "SOC overview": "Security operations overview",
            "Human review": "Human review queue",
            "Audit trail": "Audit trail",
            "Behavioral analytics": "Historical behavioral analytics",
            "Policy simulator": "Policy simulator",
            "Prompt scanner": "Explainable prompt-risk scanner",
            "Attack simulation": "Synthetic attack scenarios",
            "Agent blast radius": "Agent blast radius",
            "System telemetry": "Measured gateway and host telemetry",
        }
        for section, heading in expected_sections.items():
            app.selectbox[0].select(section).run()
            self.assertEqual(app.exception, [], msg=section)
            self.assertIn(heading, {element.value for element in app.subheader})
            info_messages = {item.value for item in app.info}
            if section == "SOC overview":
                self.assertTrue(
                    any("No persisted security events" in message for message in info_messages)
                )
            elif section == "Human review":
                self.assertTrue(
                    any("Sign in" in message for message in info_messages)
                )
            elif section == "Audit trail":
                self.assertTrue(any("Sign in" in message for message in info_messages))
            elif section == "Behavioral analytics":
                self.assertTrue(
                    any("No persisted events are available" in message for message in info_messages)
                )

    def test_dashboard_does_not_embed_api_documentation(self) -> None:
        app = self.render_dashboard()
        self.assertFalse(
            any("Open gateway API documentation" in button.label for button in app.button)
        )

    def test_overview_metrics_come_from_persisted_database_records(self) -> None:
        for request_id, verdict, risk_score in [
            ("req-dashboard-allow", "ALLOW", 10.0),
            ("req-dashboard-block", "BLOCK", 90.0),
        ]:
            self.repository.record_security_event(
                request_id=request_id,
                agent_id="agent-dashboard-test",
                action="read_demo",
                category="READ",
                resource="public/demo",
                verdict=verdict,
                risk_score=risk_score,
                risk_level="LOW" if verdict == "ALLOW" else "CRITICAL",
                reasons=["Synthetic isolated test record"],
                matched_rule_ids=["test-rule"],
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

        app = self.render_dashboard()
        displayed = {metric.label: metric.value for metric in app.metric}
        self.assertEqual(displayed["Recorded events"], "2")
        self.assertEqual(displayed["ALLOW"], "1")
        self.assertEqual(displayed["BLOCK"], "1")
        self.assertEqual(displayed["Average risk score"], "50.0/100")

    def test_empty_overview_displays_zeroes_without_demo_metrics(self) -> None:
        app = self.render_dashboard()
        displayed = {metric.label: metric.value for metric in app.metric}
        self.assertEqual(displayed["Recorded events"], "0")
        self.assertEqual(displayed["ALLOW"], "0")
        self.assertEqual(displayed["REVIEW"], "0")
        self.assertEqual(displayed["BLOCK"], "0")
        self.assertEqual(displayed["Pending reviews"], "0")
        self.assertEqual(displayed["Average risk score"], "N/A")
        self.assertTrue(
            any(
                "No persisted decision data is available" in message.value
                for message in app.info
            )
        )
        self.assertFalse(
            any("48,392" in str(element.value) for element in app.markdown)
        )

    def test_simulator_preview_does_not_persist_an_event(self) -> None:
        app = self.render_dashboard()
        app.selectbox[0].select("Policy simulator").run()
        self.assertEqual(app.exception, [])

        submit_button = next(
            button
            for button in app.button
            if button.label == "Evaluate policy preview"
        )
        submit_button.click().run()

        self.assertEqual(app.exception, [])
        self.assertIn("Policy verdict", {metric.label for metric in app.metric})
        self.assertEqual(self.repository.list_security_events(limit=10), [])
        self.assertEqual(self.repository.list_pending_reviews(limit=10), [])

    def test_malformed_simulator_json_is_rejected_without_persistence(self) -> None:
        app = self.render_dashboard()
        app.selectbox[0].select("Policy simulator").run()
        app.text_area[0].set_value("{")
        submit_button = next(
            button
            for button in app.button
            if button.label == "Evaluate policy preview"
        )
        app = submit_button.click().run()
        self.assertEqual(app.exception, [])
        self.assertTrue(
            any(item.title == "Invalid simulation input" for item in app.error)
        )
        self.assertEqual(self.repository.list_security_events(limit=10), [])


if __name__ == "__main__":
    unittest.main()
