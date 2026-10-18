"""Bounded synthetic requests for safely exercising the real gateway."""

from __future__ import annotations

import uuid
from typing import Any


SCENARIOS = {
    "prompt_injection": {
        "label": "Prompt-injection action attempt",
        "action": "prompt_injection_simulation",
        "category": "WRITE",
        "resource": "synthetic://prompt-injection",
    },
    "data_exfiltration": {
        "label": "Synthetic data export attempt",
        "action": "bulk_export_demo",
        "category": "EXPORT",
        "resource": "synthetic://records",
    },
    "unauthorized_execution": {
        "label": "Unauthorized destructive action attempt",
        "action": "delete_all",
        "category": "DELETE",
        "resource": "synthetic://demo-table",
    },
}


def build_simulation_request(scenario: str) -> dict[str, Any]:
    """Build synthetic-only input; it contains no command or customer payload."""
    try:
        template = SCENARIOS[scenario]
    except KeyError as exc:
        raise ValueError("Unknown synthetic security scenario.") from exc
    return {
        "request_id": f"sim-{scenario}-{uuid.uuid4().hex}",
        "agent_id": "synthetic-simulator",
        "action": template["action"],
        "category": template["category"],
        "resource": template["resource"],
        "parameters": {"simulation": "synthetic", "scenario": scenario},
        "claimed_permissions": [],
        "context": {"data_mode": "synthetic"},
    }
