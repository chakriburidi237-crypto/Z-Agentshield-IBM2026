"""Decision gating and execution interception layer for Z-AgentShield.

Guarantees that protected operations are never invoked unless explicitly
authorized by the policy engine and securely audited. Enforces fail-closed semantics.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from typing import Any, Callable, Collection, Optional

from zagentshield.audit.logger import AuditLogger, AuditLoggingError
from zagentshield.core.enums import ActionVerdict, RiskLevel
from zagentshield.core.models import AgentRequest, SecurityEvaluation
from zagentshield.db.repository import SecurityRepository
from zagentshield.policies.engine import PolicyEngine

logger = logging.getLogger("zagentshield.gate")

# Type alias for trusted authorization provider
TrustedAuthorizer = Callable[[str], Collection[str]]


@dataclass
class GateResult:
    """Outcome of decision gating and execution interception."""

    allowed: bool
    verdict: ActionVerdict
    evaluation: SecurityEvaluation
    ticket_id: Optional[str] = None
    execution_result: Optional[Any] = None
    error: Optional[str] = None


class DecisionGate:
    """Enforces policy evaluation and audit logging before protected operation dispatch."""

    def __init__(
        self,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger,
        repository: Optional[SecurityRepository] = None,
        authorizer: Optional[TrustedAuthorizer] = None,
        anomaly_detector: Optional[Any] = None,
    ) -> None:
        self.policy_engine = policy_engine
        self.audit_logger = audit_logger
        self.repository = repository
        self.authorizer = authorizer
        self.anomaly_detector = anomaly_detector

    def intercept_and_execute(
        self,
        request: AgentRequest,
        operation: Optional[Callable[[], Any]] = None,
        trusted_permissions: Optional[Collection[str]] = None,
        evaluation: Optional[SecurityEvaluation] = None,
    ) -> GateResult:
        """Intercept an agent action, enforce gating verdict, and execute if ALLOWed.
        
        Fail-Closed Guarantees:
        - Callbacks are NEVER executed on REVIEW, BLOCK, or any failure condition.
        - Callbacks are executed ONLY on ALLOW when audit logging succeeds.
        - Agent request claimed_permissions are unverified and cannot grant authorization.
        - Duplicate request_ids are blocked from re-execution (idempotency safety).
        
        Args:
            request: Validated AgentRequest model.
            operation: Protected operation callback to run if and only if ALLOWed.
            trusted_permissions: Server-verified trusted credentials.
            evaluation: Pre-computed SecurityEvaluation (if already evaluated).
            
        Returns:
            GateResult indicating whether execution was allowed and its outcome.
        """
        # Step 1: Input sanity check (Fail-Closed)
        if not isinstance(request, AgentRequest):
            return self._fail_closed(
                request_id="unknown",
                reason="Invalid or missing AgentRequest.",
            )

        # Step 2: Idempotency check against duplicate execution
        if self.repository is not None:
            existing_event = self.repository.get_security_event(request.request_id)
            if existing_event is not None:
                # Request has already been audited/processed. Block re-execution!
                eval_fallback = SecurityEvaluation(
                    request_id=request.request_id,
                    verdict=ActionVerdict(existing_event.verdict),
                    risk_score=existing_event.risk_score,
                    risk_level=RiskLevel(existing_event.risk_level),
                    reasons=[
                        "Duplicate request_id detected. Idempotency guard prevented re-execution."
                    ],
                    matched_rule_ids=existing_event.matched_rule_ids,
                    timestamp=datetime.now(timezone.utc),
                )
                return GateResult(
                    allowed=False,
                    verdict=eval_fallback.verdict,
                    evaluation=eval_fallback,
                    error="Duplicate request_id already processed. Execution prevented.",
                )

        # Step 3: Resolve Trusted Permissions (Server-controlled)
        resolved_trusted: Collection[str] = set()
        if trusted_permissions is not None:
            resolved_trusted = trusted_permissions
        elif self.authorizer is not None:
            try:
                resolved_trusted = self.authorizer(request.agent_id) or set()
            except Exception as e:
                logger.error("Authorizer failure for agent '%s': %s", request.agent_id, e)
                return self._fail_closed(
                    request_id=request.request_id,
                    reason=f"Authorizer lookup failed: {e}",
                )

        # Step 4: Evaluate Request against Policy Engine (if not pre-evaluated)
        active_evaluation: SecurityEvaluation
        if evaluation is not None:
            # Validate pre-computed evaluation integrity
            if (
                not isinstance(evaluation, SecurityEvaluation)
                or evaluation.request_id != request.request_id
                or evaluation.verdict not in ActionVerdict
            ):
                return self._fail_closed(
                    request_id=request.request_id,
                    reason="Malformed or mismatched SecurityEvaluation provided.",
                )
            active_evaluation = evaluation
        else:
            anomaly_assessment = None
            if self.anomaly_detector is not None:
                try:
                    anomaly_assessment = self.anomaly_detector.detect_anomalies(request)
                except Exception as e:
                    logger.error("Anomaly detector failure on request '%s': %s", request.request_id, e)
                    from zagentshield.anomalies.detector import (
                        AnomalyAssessment,
                        AnomalyCode,
                        AnomalySignal,
                    )
                    err_signal = AnomalySignal(
                        code=AnomalyCode.DETECTOR_ERROR,
                        severity=RiskLevel.MEDIUM,
                        risk_score_delta=20.0,
                        message=f"Anomaly detector error: {e}",
                    )
                    anomaly_assessment = AnomalyAssessment(
                        is_anomalous=True,
                        signals=[err_signal],
                        composite_risk_delta=20.0,
                        highest_severity=RiskLevel.MEDIUM,
                        reasons=[err_signal.message],
                    )

            try:
                active_evaluation = self.policy_engine.evaluate(
                    request=request,
                    trusted_permissions=resolved_trusted,
                    anomaly_assessment=anomaly_assessment,
                )
            except Exception as e:
                logger.error("Policy engine failure on request '%s': %s", request.request_id, e)
                return self._fail_closed(
                    request_id=request.request_id,
                    reason=f"Policy engine error: {e}",
                )

        # Step 5: Audit Persistence (Must succeed before allowing execution)
        try:
            self.audit_logger.log_evaluation(request, active_evaluation)
        except (AuditLoggingError, Exception) as e:
            logger.error("Audit failure on request '%s': %s", request.request_id, e)
            # Fail closed: never convert an audit failure into an ALLOW!
            return self._fail_closed(
                request_id=request.request_id,
                reason=f"Audit logging failed ({e}). Execution denied for integrity.",
            )

        # Step 6: Handle REVIEW Verdict (Human-in-the-Loop Gating)
        if active_evaluation.verdict == ActionVerdict.REVIEW:
            ticket_id: Optional[str] = None
            if self.repository is not None:
                ticket = self.repository.get_review_ticket_by_request_id(request.request_id)
                if ticket is not None:
                    ticket_id = ticket.ticket_id

            return GateResult(
                allowed=False,
                verdict=ActionVerdict.REVIEW,
                evaluation=active_evaluation,
                ticket_id=ticket_id,
                error="Action requires human-in-the-loop review. Execution denied.",
            )

        # Step 7: Handle BLOCK Verdict (Mandatory Deny)
        if active_evaluation.verdict == ActionVerdict.BLOCK:
            return GateResult(
                allowed=False,
                verdict=ActionVerdict.BLOCK,
                evaluation=active_evaluation,
                error="Action blocked by security policy.",
            )

        # Step 8: Handle ALLOW Verdict (Execute protected operation callback)
        if active_evaluation.verdict == ActionVerdict.ALLOW:
            execution_res: Optional[Any] = None
            exec_err: Optional[str] = None

            if operation is not None:
                try:
                    execution_res = operation()
                except Exception as e:
                    logger.error("Protected operation error on request '%s': %s", request.request_id, e)
                    exec_err = f"Protected operation raised an exception: {e}"

            return GateResult(
                allowed=True,
                verdict=ActionVerdict.ALLOW,
                evaluation=active_evaluation,
                execution_result=execution_res,
                error=exec_err,
            )

        # Catch-all unexpected verdict (Fail-closed)
        return self._fail_closed(
            request_id=request.request_id,
            reason=f"Unrecognized verdict '{active_evaluation.verdict}'.",
        )

    def execute_approved_ticket(
        self,
        ticket_id: str,
        operation: Callable[[], Any],
        reviewer_id: str,
    ) -> GateResult:
        """Execute a previously reviewed operation only if its ticket is explicitly APPROVED.
        
        Guarantees that pending or rejected tickets cannot be executed.
        """
        if self.repository is None:
            return self._fail_closed(
                request_id=ticket_id,
                reason="Repository not configured for review ticket retrieval.",
            )

        ticket = self.repository.get_review_ticket(ticket_id)
        if ticket is None:
            return self._fail_closed(
                request_id=ticket_id,
                reason=f"Review ticket '{ticket_id}' not found.",
            )

        if ticket.status != "APPROVED":
            return GateResult(
                allowed=False,
                verdict=ActionVerdict.BLOCK,
                evaluation=SecurityEvaluation(
                    request_id=ticket.request_id,
                    verdict=ActionVerdict.BLOCK,
                    risk_score=ticket.risk_score,
                    risk_level=RiskLevel(ticket.risk_level),
                    reasons=[
                        f"Ticket '{ticket_id}' is in status '{ticket.status}', not APPROVED."
                    ],
                    matched_rule_ids=[],
                    timestamp=datetime.now(timezone.utc),
                ),
                ticket_id=ticket_id,
                error=f"Execution rejected: Ticket is '{ticket.status}'.",
            )

        # Ticket is APPROVED: Execute protected callback safely
        execution_res: Optional[Any] = None
        exec_err: Optional[str] = None
        try:
            execution_res = operation()
        except Exception as e:
            exec_err = f"Approved operation failed during execution: {e}"

        return GateResult(
            allowed=True,
            verdict=ActionVerdict.ALLOW,
            evaluation=SecurityEvaluation(
                request_id=ticket.request_id,
                verdict=ActionVerdict.ALLOW,
                risk_score=ticket.risk_score,
                risk_level=RiskLevel(ticket.risk_level),
                reasons=[f"Executed under approved human review ticket '{ticket_id}' by '{reviewer_id}'."],
                matched_rule_ids=[],
                timestamp=datetime.now(timezone.utc),
            ),
            ticket_id=ticket_id,
            execution_result=execution_res,
            error=exec_err,
        )

    @staticmethod
    def _fail_closed(request_id: str, reason: str) -> GateResult:
        """Construct an immutable BLOCK outcome for fail-closed scenarios."""
        fallback_eval = SecurityEvaluation(
            request_id=request_id if request_id else "unknown",
            verdict=ActionVerdict.BLOCK,
            risk_score=100.0,
            risk_level=RiskLevel.CRITICAL,
            reasons=[f"Fail-closed defense triggered: {reason}"],
            matched_rule_ids=[],
            timestamp=datetime.now(timezone.utc),
        )
        return GateResult(
            allowed=False,
            verdict=ActionVerdict.BLOCK,
            evaluation=fallback_eval,
            error=reason,
        )
