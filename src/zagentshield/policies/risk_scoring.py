"""Explainable risk scoring engine for Z-AgentShield.

Evaluates multi-factor risk signals including action category, resource sensitivity,
parameter blast radius, and authorization trust discrepancy.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Collection, Dict, List, Optional, Set

from zagentshield.core.enums import ActionCategory, RiskLevel
from zagentshield.core.models import AgentRequest, PolicyRule


@dataclass(frozen=True)
class RiskSignal:
    """An explainable risk signal contributing to the composite score."""

    name: str
    weight: float
    description: str


@dataclass
class RiskAssessment:
    """The result of an explainable risk evaluation."""

    risk_score: float
    risk_level: RiskLevel
    contributing_signals: List[str] = field(default_factory=list)


# Category baseline weights
CATEGORY_RISK_BASELINES: Dict[ActionCategory, float] = {
    ActionCategory.READ: 10.0,
    ActionCategory.WRITE: 30.0,
    ActionCategory.UPDATE: 35.0,
    ActionCategory.EXPORT: 50.0,
    ActionCategory.DELETE: 60.0,
    ActionCategory.ADMIN: 75.0,
}

# Suspicious SQL / command patterns for blast radius detection
SUSPICIOUS_PARAM_PATTERNS = [
    re.compile(r"(?i)\b(drop\s+table|truncate\s+table|union\s+select|exec\s*\(|;\s*--)"),
    re.compile(r"(?i)(/bin/sh|/bin/bash|cmd\.exe|powershell)"),
]


class RiskScorer:
    """Calculates explainable risk scores on a 0.0 to 100.0 scale."""

    def __init__(self) -> None:
        pass

    def evaluate_risk(
        self,
        request: AgentRequest,
        trusted_permissions: Optional[Collection[str]] = None,
        matched_rules: Optional[List[PolicyRule]] = None,
        anomaly_signals: Optional[List[RiskSignal]] = None,
    ) -> RiskAssessment:
        """Calculate a composite risk score from distinct, non-overlapping signals.
        
        Args:
            request: The intercepted agent action request.
            trusted_permissions: Verified permissions possessed by the caller.
            matched_rules: Any policy rules matched during policy engine evaluation.
            
        Returns:
            RiskAssessment with score [0.0 - 100.0], risk level, and reasons.
        """
        signals: List[RiskSignal] = []
        trusted_set: Set[str] = set(trusted_permissions) if trusted_permissions else set()

        # Signal 1: Action Category Baseline Risk
        cat_baseline = CATEGORY_RISK_BASELINES.get(request.category, 20.0)
        signals.append(
            RiskSignal(
                name="category_baseline",
                weight=cat_baseline,
                description=f"Action category '{request.category.value}' baseline risk (+{cat_baseline:.1f})",
            )
        )

        # Signal 2: Target Resource Sensitivity (Highest tier only to avoid double counting)
        res_lower = request.resource.lower()
        if any(prefix in res_lower for prefix in ("secrets://", "vault://", "credentials://", "system://shell", "kms://")):
            signals.append(
                RiskSignal(
                    name="resource_critical",
                    weight=35.0,
                    description=f"Target resource '{request.resource}' is within a critical security tier (+35.0)",
                )
            )
        elif re.search(r"(?i)\b(prod|production|finance|payments|iam|auth)\b", res_lower):
            signals.append(
                RiskSignal(
                    name="resource_high",
                    weight=20.0,
                    description=f"Target resource '{request.resource}' contains sensitive production or financial scope (+20.0)",
                )
            )
        elif re.search(r"(?i)\b(customer|user_data|reporting)\b", res_lower):
            signals.append(
                RiskSignal(
                    name="resource_medium",
                    weight=10.0,
                    description=f"Target resource '{request.resource}' accesses internal customer or reporting data (+10.0)",
                )
            )

        # Signal 3: Parameter Blast Radius / Volume Indicators
        blast_signal = self._evaluate_parameter_blast_radius(request.parameters)
        if blast_signal is not None:
            signals.append(blast_signal)

        # Signal 4: Authorization Discrepancy Signal
        # Check if the agent claimed permissions that are NOT trusted
        if request.claimed_permissions:
            untrusted_claims = [p for p in request.claimed_permissions if p not in trusted_set]
            if untrusted_claims:
                signals.append(
                    RiskSignal(
                        name="unverified_permission_claim",
                        weight=20.0,
                        description=(
                            f"Agent claimed unverified permissions {untrusted_claims} "
                            "not present in trusted credentials (+20.0)"
                        ),
                    )
                )
        elif not trusted_set and request.category != ActionCategory.READ:
            signals.append(
                RiskSignal(
                    name="missing_trusted_auth",
                    weight=15.0,
                    description="Action requested without any trusted credentials provided (+15.0)",
                )
            )

        # Signal 5: Matched Rule Baseline Contribution
        rule_max_score = 0.0
        if matched_rules:
            enabled_rules = [r for r in matched_rules if r.enabled]
            if enabled_rules:
                rule_max_score = max(r.base_risk_score for r in enabled_rules)
                highest_rule = max(enabled_rules, key=lambda r: r.base_risk_score)
                signals.append(
                    RiskSignal(
                        name="policy_rule_match",
                        weight=rule_max_score * 0.3,  # Scaled additive factor
                        description=f"Matched policy rule '{highest_rule.rule_id}' (severity: {highest_rule.severity.value})",
                    )
                )

        # Signal 6: Anomaly Detection Signals
        if anomaly_signals:
            signals.extend(anomaly_signals)

        # Composite Calculation:
        # Sum non-overlapping signals, but ensure score does not fall below the highest matched rule baseline
        summed_weight = sum(s.weight for s in signals)
        raw_score = max(summed_weight, rule_max_score)
        clamped_score = max(0.0, min(100.0, round(raw_score, 1)))

        # Categorize Risk Level
        risk_level = self._score_to_level(clamped_score)

        return RiskAssessment(
            risk_score=clamped_score,
            risk_level=risk_level,
            contributing_signals=[s.description for s in signals],
        )

    def _evaluate_parameter_blast_radius(self, params: Dict[str, Any]) -> Optional[RiskSignal]:
        """Detect high blast radius or suspicious query fragments in parameters."""
        if not params:
            return None

        # Check for bulk / unbounded indicators
        bulk_keys = {"limit", "count", "batch_size", "size"}
        for k, v in params.items():
            if k.lower() in bulk_keys and isinstance(v, (int, float)) and v > 500:
                return RiskSignal(
                    name="high_volume_limit",
                    weight=15.0,
                    description=f"High record count parameter ({k}={v}) indicates elevated blast radius (+15.0)",
                )

        for k, v in params.items():
            if k.lower() in ("bulk", "all", "recursive", "purge") and v is True:
                return RiskSignal(
                    name="bulk_flag_enabled",
                    weight=15.0,
                    description=f"Bulk execution flag '{k}=True' increases operational blast radius (+15.0)",
                )

        # Check for injection syntax strings
        for v in params.values():
            if isinstance(v, str):
                for pattern in SUSPICIOUS_PARAM_PATTERNS:
                    if pattern.search(v):
                        return RiskSignal(
                            name="suspicious_parameter_content",
                            weight=25.0,
                            description="Suspicious execution syntax or query pattern detected in parameter (+25.0)",
                        )

        return None

    @staticmethod
    def _score_to_level(score: float) -> RiskLevel:
        """Map a 0.0-100.0 score to a categorical RiskLevel."""
        if score <= 25.0:
            return RiskLevel.LOW
        if score <= 50.0:
            return RiskLevel.MEDIUM
        if score <= 75.0:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL
