"""API-facing schemas for Z-AgentShield request interception and response gating.

Ensures inputs are strictly validated and outgoing responses do not leak sensitive payloads.
"""

from datetime import datetime, timezone
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from zagentshield.core.enums import ActionCategory, ActionVerdict, RiskLevel
from zagentshield.core.models import AgentRequest, SecurityEvaluation, ID_PATTERN, ensure_utc


class InterceptRequest(BaseModel):
    """Payload sent by an agent or gateway seeking execution authorization."""

    request_id: Optional[str] = Field(
        default=None,
        description="Optional client-provided unique request identifier. Auto-generated if omitted.",
        max_length=128,
    )
    agent_id: str = Field(
        ...,
        description="Identifier of the requesting AI agent.",
        min_length=1,
        max_length=128,
    )
    action: str = Field(
        ...,
        description="Name of the action to be performed.",
        min_length=1,
        max_length=256,
    )
    category: ActionCategory = Field(
        ...,
        description="Functional category of the action.",
    )
    resource: str = Field(
        ...,
        description="Target resource URI or identifier.",
        min_length=1,
        max_length=512,
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters associated with the requested action.",
    )
    claimed_permissions: List[str] = Field(
        default_factory=list,
        description="Permissions claimed by the caller (evaluated by policy rules, not self-authorizing).",
    )
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Contextual metadata (e.g. user ID, session ID, tenant).",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of request origination in UTC.",
    )

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "agent_id": "agent-finance-01",
                "action": "export_customer_data",
                "category": "EXPORT",
                "resource": "data://customers/financial_records",
                "parameters": {
                    "records": 5000,
                    "format": "csv"
                },
                "claimed_permissions": [],
                "context": {"session_id": "sess-123"}
            }
        },
    )

    @field_validator("request_id")
    @classmethod
    def validate_request_id_optional(cls, value: Optional[str]) -> Optional[str]:
        """Validate format if request_id is supplied."""
        if value is not None and not ID_PATTERN.match(value):
            raise ValueError(f"Invalid request_id format: '{value}'.")
        return value

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, value: str) -> str:
        """Validate agent identifier format."""
        if not ID_PATTERN.match(value):
            raise ValueError(f"Invalid agent_id format: '{value}'.")
        return value

    def to_agent_request(self) -> AgentRequest:
        """Convert interception request into the canonical domain AgentRequest."""
        req_id = self.request_id or f"req-{uuid.uuid4().hex[:16]}"
        return AgentRequest(
            request_id=req_id,
            agent_id=self.agent_id,
            action=self.action,
            category=self.category,
            resource=self.resource,
            parameters=self.parameters,
            claimed_permissions=self.claimed_permissions,
            context=self.context,
            timestamp=self.timestamp,
        )


class InterceptResponse(BaseModel):
    """Sanitized evaluation response returned to the caller.
    
    Exposes verdict and risk rationale without echoing sensitive payload parameters.
    """

    request_id: str = Field(
        ...,
        description="Identifier of the evaluated request.",
    )
    verdict: ActionVerdict = Field(
        ...,
        description="Action decision: ALLOW, REVIEW, or BLOCK.",
    )
    allowed: bool = Field(
        ...,
        description="Convenience boolean flag. True only when verdict is ALLOW.",
    )
    review_required: bool = Field(
        ...,
        description="Convenience boolean flag. True when verdict is REVIEW.",
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Composite risk score (0.0 - 100.0).",
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Categorical risk rating.",
    )
    reasons: List[str] = Field(
        default_factory=list,
        description="Human-readable decision rationales.",
    )
    matched_rule_ids: List[str] = Field(
        default_factory=list,
        description="List of policy rule IDs triggered during evaluation.",
    )
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when evaluation completed.",
    )

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    @classmethod
    def from_evaluation(cls, evaluation: SecurityEvaluation) -> "InterceptResponse":
        """Construct response securely from a SecurityEvaluation domain object."""
        return cls(
            request_id=evaluation.request_id,
            verdict=evaluation.verdict,
            allowed=(evaluation.verdict == ActionVerdict.ALLOW),
            review_required=(evaluation.verdict == ActionVerdict.REVIEW),
            risk_score=evaluation.risk_score,
            risk_level=evaluation.risk_level,
            reasons=evaluation.reasons,
            matched_rule_ids=evaluation.matched_rule_ids,
            evaluated_at=evaluation.timestamp,
        )


class HealthResponse(BaseModel):
    """Health status response."""

    status: str = "ok"
    version: str = "0.1.0"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
