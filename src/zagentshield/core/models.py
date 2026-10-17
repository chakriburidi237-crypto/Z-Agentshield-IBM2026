"""Core domain models for Z-AgentShield.

Defines schemas for intercepted agent requests, policy rules, and security evaluations.
"""

from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from zagentshield.core.enums import ActionCategory, ActionVerdict, RiskLevel

# Pattern for safe identifiers (alphanumeric with underscores, hyphens, colons, and dots)
ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.:]{1,128}$")


def ensure_utc(dt: Optional[datetime]) -> datetime:
    """Ensure a datetime is timezone-aware UTC."""
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class AgentRequest(BaseModel):
    """Represents an intercepted action request initiated by an AI agent.
    
    NOTE: Claimed permissions in this request are unverified inputs provided
    by the caller/agent context. They MUST NOT be assumed to prove authorization.
    """

    request_id: str = Field(
        ...,
        description="Unique identifier for the action request.",
        min_length=1,
        max_length=128,
    )
    agent_id: str = Field(
        ...,
        description="Identifier of the AI agent attempting the action.",
        min_length=1,
        max_length=128,
    )
    action: str = Field(
        ...,
        description="Operation name requested by the agent.",
        min_length=1,
        max_length=256,
    )
    category: ActionCategory = Field(
        ...,
        description="Broad category of the operation.",
    )
    resource: str = Field(
        ...,
        description="Target resource URI or identifier.",
        min_length=1,
        max_length=512,
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Action-specific parameters or arguments passed by the agent.",
    )
    claimed_permissions: List[str] = Field(
        default_factory=list,
        description="Permissions claimed by the agent (unverified until policy engine evaluation).",
    )
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Supplemental runtime execution context (e.g. session_id, tenant_id).",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Time the request was captured in UTC.",
    )

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    @field_validator("request_id", "agent_id")
    @classmethod
    def validate_identifier_format(cls, value: str) -> str:
        """Validate that identifiers follow safe naming constraints."""
        if not ID_PATTERN.match(value):
            raise ValueError(
                f"Invalid identifier format: '{value}'. Must be 1-128 alphanumeric characters, '.', ':', '-', or '_'."
            )
        return value

    @field_validator("action", "resource")
    @classmethod
    def validate_non_empty_string(cls, value: str) -> str:
        """Ensure string fields contain meaningful content."""
        if not value or not value.strip():
            raise ValueError("Field must not be empty or whitespace only.")
        return value.strip()

    @field_validator("claimed_permissions")
    @classmethod
    def validate_permissions(cls, perms: List[str]) -> List[str]:
        """Validate and clean claimed permission tokens."""
        cleaned: List[str] = []
        for p in perms:
            if not isinstance(p, str) or not p.strip():
                raise ValueError("Permission entries must be non-empty strings.")
            cleaned.append(p.strip())
        return cleaned

    @field_validator("timestamp", mode="before")
    @classmethod
    def coerce_utc_timestamp(cls, value: Any) -> datetime:
        """Coerce timestamp to timezone-aware UTC datetime."""
        if isinstance(value, str):
            try:
                dt = datetime.fromisoformat(value)
                return ensure_utc(dt)
            except Exception as e:
                raise ValueError(f"Invalid timestamp format: {e}") from e
        elif isinstance(value, datetime):
            return ensure_utc(value)
        elif value is None:
            return datetime.now(timezone.utc)
        raise ValueError("Timestamp must be an ISO format string or datetime instance.")


class PolicyRule(BaseModel):
    """Defines an enterprise security policy rule."""

    rule_id: str = Field(
        ...,
        description="Unique identifier for the policy rule.",
        min_length=1,
        max_length=128,
    )
    description: str = Field(
        ...,
        description="Human-readable description of the policy rule.",
        min_length=1,
        max_length=1024,
    )
    applicable_action: str = Field(
        ...,
        description="Action pattern or wildcard to which this rule applies.",
        min_length=1,
        max_length=256,
    )
    applicable_resource: str = Field(
        ...,
        description="Resource pattern or wildcard to which this rule applies.",
        min_length=1,
        max_length=512,
    )
    category: Optional[ActionCategory] = Field(
        default=None,
        description="Optional action category constraint.",
    )
    required_permissions: List[str] = Field(
        default_factory=list,
        description="List of permissions required to permit this operation.",
    )
    severity: RiskLevel = Field(
        default=RiskLevel.MEDIUM,
        description="Severity level associated with violations of this rule.",
    )
    base_risk_score: float = Field(
        default=50.0,
        ge=0.0,
        le=100.0,
        description="Baseline risk score contribution (0.0 to 100.0).",
    )
    enabled: bool = Field(
        default=True,
        description="Whether this policy rule is currently active.",
    )
    verdict: Optional[ActionVerdict] = Field(
        default=None,
        description="Optional explicit verdict enforced by this rule (ALLOW, REVIEW, or BLOCK).",
    )

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    @field_validator("rule_id")
    @classmethod
    def validate_rule_id_format(cls, value: str) -> str:
        """Validate rule identifier pattern."""
        if not ID_PATTERN.match(value):
            raise ValueError(
                f"Invalid rule_id format: '{value}'. Must be 1-128 alphanumeric characters, '.', ':', '-', or '_'."
            )
        return value

    @field_validator("description", "applicable_action", "applicable_resource")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        """Ensure string fields contain meaningful content."""
        if not value or not value.strip():
            raise ValueError("Field must not be empty or whitespace only.")
        return value.strip()


class SecurityEvaluation(BaseModel):
    """The result of evaluating an agent request against security policies and anomalies."""

    request_id: str = Field(
        ...,
        description="Identifier of the evaluated request.",
        min_length=1,
        max_length=128,
    )
    verdict: ActionVerdict = Field(
        ...,
        description="Final action gate verdict: ALLOW, REVIEW, or BLOCK.",
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Calculated composite risk score on a 0.0 to 100.0 scale.",
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Categorical risk classification corresponding to the risk score.",
    )
    reasons: List[str] = Field(
        default_factory=list,
        description="List of explanatory reasons for the verdict and risk score.",
    )
    matched_rule_ids: List[str] = Field(
        default_factory=list,
        description="IDs of policy rules that were triggered or matched during evaluation.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the evaluation was finalized in UTC.",
    )

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        """Validate request ID format."""
        if not ID_PATTERN.match(value):
            raise ValueError(f"Invalid request_id format: '{value}'.")
        return value

    @field_validator("timestamp", mode="before")
    @classmethod
    def coerce_utc_timestamp(cls, value: Any) -> datetime:
        """Coerce timestamp to timezone-aware UTC datetime."""
        if isinstance(value, str):
            try:
                dt = datetime.fromisoformat(value)
                return ensure_utc(dt)
            except Exception as e:
                raise ValueError(f"Invalid timestamp format: {e}") from e
        elif isinstance(value, datetime):
            return ensure_utc(value)
        elif value is None:
            return datetime.now(timezone.utc)
        raise ValueError("Timestamp must be an ISO format string or datetime instance.")

    @model_validator(mode="after")
    def validate_verdict_reasons(self) -> "SecurityEvaluation":
        """Ensure BLOCK and REVIEW decisions include explanatory reasons."""
        if self.verdict in (ActionVerdict.BLOCK, ActionVerdict.REVIEW) and not self.reasons:
            raise ValueError(f"A '{self.verdict.value}' verdict must include at least one explanatory reason.")
        return self
