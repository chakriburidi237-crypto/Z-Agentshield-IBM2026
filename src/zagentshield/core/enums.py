"""Core enumeration types for Z-AgentShield.

Defines verdicts, action categories, and risk severity levels.
"""

from enum import Enum


class ActionVerdict(str, Enum):
    """Tri-state action evaluation verdicts."""

    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class ActionCategory(str, Enum):
    """Functional categories of operations an AI agent can request."""

    READ = "READ"
    WRITE = "WRITE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    EXPORT = "EXPORT"
    ADMIN = "ADMIN"


class RiskLevel(str, Enum):
    """Risk severity classifications."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
