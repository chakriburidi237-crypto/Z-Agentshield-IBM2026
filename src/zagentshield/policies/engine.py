"""Policy evaluation engine for Z-AgentShield.

Evaluates intercepted AI agent action requests against structured security policies.
Enforces strict precedence: Mandatory Deny -> Human Review -> Explicit Allow -> Default Deny.
"""

from datetime import datetime, timezone
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Collection, Dict, List, Optional, Set, Tuple, Union
import yaml
from pydantic import BaseModel, Field, ValidationError

from zagentshield.core.enums import ActionVerdict, RiskLevel
from zagentshield.core.models import AgentRequest, PolicyRule, SecurityEvaluation
from zagentshield.policies.risk_scoring import RiskAssessment, RiskScorer


class PolicyConfigurationError(Exception):
    """Raised when the policy configuration is missing, malformed, or invalid."""


class PolicyConfig(BaseModel):
    """Schema for validating policies.yaml."""

    version: str = "1.0"
    description: Optional[str] = None
    default_verdict: ActionVerdict = ActionVerdict.BLOCK
    deny_rules: List[PolicyRule] = Field(default_factory=list)
    review_rules: List[PolicyRule] = Field(default_factory=list)
    allow_rules: List[PolicyRule] = Field(default_factory=list)


def _matches_pattern(value: str, pattern_spec: str) -> bool:
    """Check if a string matches a wildcard or pipe-delimited pattern set."""
    if pattern_spec == "*":
        return True
    patterns = [p.strip() for p in pattern_spec.split("|") if p.strip()]
    return any(fnmatchcase(value, pat) for pat in patterns)


def _rule_matches_request(rule: PolicyRule, request: AgentRequest) -> bool:
    """Determine if a PolicyRule applies to an AgentRequest."""
    if not rule.enabled:
        return False

    if rule.category is not None and rule.category != request.category:
        return False

    if not _matches_pattern(request.action, rule.applicable_action):
        return False

    if not _matches_pattern(request.resource, rule.applicable_resource):
        return False

    return True


class PolicyEngine:
    """Deterministic security policy evaluation engine for AI Agent actions."""

    def __init__(
        self,
        config: PolicyConfig,
        risk_threshold_review: float = 40.0,
        risk_threshold_block: float = 75.0,
        risk_scorer: Optional[RiskScorer] = None,
    ) -> None:
        self.config = config
        self.risk_threshold_review = risk_threshold_review
        self.risk_threshold_block = risk_threshold_block
        self.risk_scorer = risk_scorer or RiskScorer()

    @classmethod
    def from_yaml_file(
        cls,
        file_path: Union[str, Path],
        risk_threshold_review: float = 40.0,
        risk_threshold_block: float = 75.0,
    ) -> "PolicyEngine":
        """Load and validate policy configuration from a YAML file.
        
        Fails closed by raising PolicyConfigurationError on any parsing or validation failure.
        """
        path = Path(file_path)
        if not path.is_file():
            raise PolicyConfigurationError(f"Policy file not found: {path.resolve()}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                raw_data = yaml.safe_load(f)
        except Exception as e:
            raise PolicyConfigurationError(f"Failed to parse YAML policy file: {e}") from e

        if not isinstance(raw_data, dict):
            raise PolicyConfigurationError("Policy file content must be a YAML dictionary mapping.")

        try:
            policy_config = PolicyConfig.model_validate(raw_data)
        except ValidationError as e:
            raise PolicyConfigurationError(f"Policy configuration validation failed: {e}") from e

        return cls(
            config=policy_config,
            risk_threshold_review=risk_threshold_review,
            risk_threshold_block=risk_threshold_block,
        )

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
        risk_threshold_review: float = 40.0,
        risk_threshold_block: float = 75.0,
    ) -> "PolicyEngine":
        """Load policy engine directly from a dictionary."""
        try:
            policy_config = PolicyConfig.model_validate(data)
        except ValidationError as e:
            raise PolicyConfigurationError(f"Policy dictionary validation failed: {e}") from e

        return cls(
            config=policy_config,
            risk_threshold_review=risk_threshold_review,
            risk_threshold_block=risk_threshold_block,
        )

    def evaluate(
        self,
        request: AgentRequest,
        trusted_permissions: Optional[Collection[str]] = None,
        trusted_context: Optional[Dict[str, Any]] = None,
        anomaly_assessment: Optional[Any] = None,
    ) -> SecurityEvaluation:
        """Evaluate an intercepted action request against security policies and risk signals.
        
        Args:
            request: Intercepted agent action request.
            trusted_permissions: Cryptographically verified or system-validated permissions.
                                 Note: request.claimed_permissions is untrusted input and
                                 is ignored for granting access.
            trusted_context: Verified environmental or caller context.
            
        Returns:
            SecurityEvaluation domain model with deterministic verdict, score, and reasons.
        """
        trusted_set: Set[str] = set(trusted_permissions) if trusted_permissions else set()
        matched_rule_ids: List[str] = []
        matched_rules: List[PolicyRule] = []
        reasons: List[str] = []

        # ----------------------------------------------------------------------
        # Step 1: Mandatory Deny Rules Evaluation
        # Deny rules ALWAYS take precedence. If any deny rule triggers, the
        # action is BLOCKED immediately regardless of trusted credentials.
        # ----------------------------------------------------------------------
        for deny_rule in self.config.deny_rules:
            if _rule_matches_request(deny_rule, request):
                matched_rule_ids.append(deny_rule.rule_id)
                matched_rules.append(deny_rule)
                reasons.append(
                    f"Prohibited action blocked by policy rule '{deny_rule.rule_id}': {deny_rule.description}"
                )

        if matched_rule_ids:
            # Deny rule matched: Mandatory BLOCK
            risk_assessment = self.risk_scorer.evaluate_risk(
                request=request,
                trusted_permissions=trusted_set,
                matched_rules=matched_rules,
            )
            # Add risk breakdown into explanatory reasons
            reasons.extend(risk_assessment.contributing_signals)
            return SecurityEvaluation(
                request_id=request.request_id,
                verdict=ActionVerdict.BLOCK,
                risk_score=risk_assessment.risk_score,
                risk_level=risk_assessment.risk_level,
                reasons=reasons,
                matched_rule_ids=matched_rule_ids,
                timestamp=datetime.now(timezone.utc),
            )

        # ----------------------------------------------------------------------
        # Step 2: Human-in-the-Loop Review Rules Evaluation
        # ----------------------------------------------------------------------
        review_matched = False
        for rev_rule in self.config.review_rules:
            if _rule_matches_request(rev_rule, request):
                matched_rule_ids.append(rev_rule.rule_id)
                matched_rules.append(rev_rule)
                # Check if review rule itself demands baseline trusted permissions
                if rev_rule.required_permissions:
                    missing = [p for p in rev_rule.required_permissions if p not in trusted_set]
                    if missing:
                        # Lacks trusted permissions to even request this reviewable action
                        reasons.append(
                            f"Missing trusted authorization for '{rev_rule.rule_id}': "
                            f"Required permission(s) {missing} not present in trusted credentials."
                        )
                        risk_assessment = self.risk_scorer.evaluate_risk(
                            request=request,
                            trusted_permissions=trusted_set,
                            matched_rules=matched_rules,
                        )
                        reasons.extend(risk_assessment.contributing_signals)
                        return SecurityEvaluation(
                            request_id=request.request_id,
                            verdict=ActionVerdict.BLOCK,
                            risk_score=risk_assessment.risk_score,
                            risk_level=risk_assessment.risk_level,
                            reasons=reasons,
                            matched_rule_ids=matched_rule_ids,
                            timestamp=datetime.now(timezone.utc),
                        )

                reasons.append(
                    f"Escalated to human review by policy rule '{rev_rule.rule_id}': {rev_rule.description}"
                )
                review_matched = True

        # ----------------------------------------------------------------------
        # Step 3: Explicit Allow Rules Evaluation
        # ----------------------------------------------------------------------
        allow_matched = False
        permission_failure = False

        for allow_rule in self.config.allow_rules:
            if _rule_matches_request(allow_rule, request):
                matched_rule_ids.append(allow_rule.rule_id)
                matched_rules.append(allow_rule)

                # Verify that all required permissions are held in trusted_set
                if allow_rule.required_permissions:
                    missing_perms = [p for p in allow_rule.required_permissions if p not in trusted_set]
                    if missing_perms:
                        permission_failure = True
                        reasons.append(
                            f"Missing trusted authorization for '{allow_rule.rule_id}': "
                            f"Required permission(s) {missing_perms} not verified."
                        )
                        continue

                allow_matched = True
                reasons.append(
                    f"Permitted by policy rule '{allow_rule.rule_id}': {allow_rule.description}"
                )
                break

        # ----------------------------------------------------------------------
        # Step 4: Determine Preliminary Verdict
        # ----------------------------------------------------------------------
        if review_matched:
            candidate_verdict = ActionVerdict.REVIEW
        elif allow_matched:
            candidate_verdict = ActionVerdict.ALLOW
        elif permission_failure:
            candidate_verdict = ActionVerdict.BLOCK
            # reasons already contain missing permission detail
        else:
            # Default-Deny: Action did not match any permitted allow rule
            candidate_verdict = self.config.default_verdict
            reasons.append(
                f"Default-Deny: Requested action '{request.action}' on resource '{request.resource}' "
                "does not match any authorized allow rule."
            )

        # ----------------------------------------------------------------------
        # Step 5: Risk Scoring & Threshold Gating
        # ----------------------------------------------------------------------
        anomaly_risk_signals: List[Any] = []
        if anomaly_assessment is not None and getattr(anomaly_assessment, "is_anomalous", False):
            for sig in getattr(anomaly_assessment, "signals", []):
                from zagentshield.policies.risk_scoring import RiskSignal
                anomaly_risk_signals.append(
                    RiskSignal(
                        name=f"anomaly_{getattr(sig.code, 'value', str(sig.code)).lower()}",
                        weight=sig.risk_score_delta,
                        description=sig.message,
                    )
                )

        risk_assessment = self.risk_scorer.evaluate_risk(
            request=request,
            trusted_permissions=trusted_set,
            matched_rules=matched_rules,
            anomaly_signals=anomaly_risk_signals,
        )
        reasons.extend(risk_assessment.contributing_signals)

        final_verdict = candidate_verdict

        # Apply anomaly severity escalation for candidate ALLOW
        if candidate_verdict == ActionVerdict.ALLOW and anomaly_assessment is not None and getattr(anomaly_assessment, "is_anomalous", False):
            sev = getattr(anomaly_assessment, "highest_severity", None)
            if sev == RiskLevel.CRITICAL:
                final_verdict = ActionVerdict.BLOCK
                reasons.insert(0, "Critical behavioral anomaly detected; execution blocked.")
            elif sev in (RiskLevel.HIGH, RiskLevel.MEDIUM):
                final_verdict = ActionVerdict.REVIEW
                reasons.insert(0, "Behavioral anomaly detected; escalated to human review.")

        # Apply risk threshold escalations for candidate ALLOW
        # (ALLOW -> REVIEW or BLOCK).
        # CRITICAL RULE: Never allow a low risk score to override a mandatory BLOCK!
        # Actions matched to review_rules explicitly belong in the human review queue.
        if final_verdict == ActionVerdict.ALLOW:
            if risk_assessment.risk_score >= self.risk_threshold_block:
                final_verdict = ActionVerdict.BLOCK
                reasons.insert(
                    0,
                    f"Elevated risk score ({risk_assessment.risk_score:.1f} >= {self.risk_threshold_block:.1f}) "
                    "triggered automatic block.",
                )
            elif risk_assessment.risk_score >= self.risk_threshold_review:
                final_verdict = ActionVerdict.REVIEW
                reasons.insert(
                    0,
                    f"Elevated risk score ({risk_assessment.risk_score:.1f} >= {self.risk_threshold_review:.1f}) "
                    "requires human review.",
                )

        return SecurityEvaluation(
            request_id=request.request_id,
            verdict=final_verdict,
            risk_score=risk_assessment.risk_score,
            risk_level=risk_assessment.risk_level,
            reasons=reasons,
            matched_rule_ids=matched_rule_ids,
            timestamp=datetime.now(timezone.utc),
        )
