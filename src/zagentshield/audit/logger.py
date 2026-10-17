"""Secure audit logging module for Z-AgentShield.

Records sanitized evaluation events into the tamper-evident audit database.
Integrates sensitive-data redaction and review-queue ticket generation.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional

from zagentshield.audit.redaction import redact_sensitive_data
from zagentshield.core.enums import ActionVerdict
from zagentshield.core.models import AgentRequest, SecurityEvaluation
from zagentshield.db.repository import ReviewTicketRecord, SecurityRepository

logger = logging.getLogger("zagentshield.audit")


class AuditLoggingError(Exception):
    """Raised when an audit record fails to persist.
    
    CRITICAL: A failure in audit logging MUST NEVER cause a rejected action
    to be treated as an implicit ALLOW.
    """


class AuditLogger:
    """Manages audit persistence with automatic sensitive-data redaction."""

    def __init__(self, repository: SecurityRepository) -> None:
        self.repository = repository

    def log_evaluation(
        self,
        request: AgentRequest,
        evaluation: SecurityEvaluation,
    ) -> bool:
        """Record an evaluated agent request into the audit log and review queue.
        
        Args:
            request: The intercepted AgentRequest.
            evaluation: The resulting SecurityEvaluation.
            
        Returns:
            True if audit log recorded successfully, False otherwise.
            
        Raises:
            AuditLoggingError: If strict audit persistence fails.
        """
        try:
            # Step 1: Redact any sensitive keys and inline secret patterns from parameters
            redacted_params = redact_sensitive_data(request.parameters)

            # Step 2: Record into security_events audit table
            inserted = self.repository.record_security_event(
                request_id=request.request_id,
                agent_id=request.agent_id,
                action=request.action,
                category=request.category.value,
                resource=request.resource,
                verdict=evaluation.verdict.value,
                risk_score=evaluation.risk_score,
                risk_level=evaluation.risk_level.value,
                reasons=evaluation.reasons,
                matched_rule_ids=evaluation.matched_rule_ids,
                parameters_redacted=redacted_params,
                timestamp=evaluation.timestamp.isoformat(),
            )

            # Step 3: If action requires human review, create a ticket in review_queue
            if evaluation.verdict == ActionVerdict.REVIEW and inserted:
                self.repository.create_review_ticket(
                    request_id=request.request_id,
                    agent_id=request.agent_id,
                    action=request.action,
                    category=request.category.value,
                    resource=request.resource,
                    risk_score=evaluation.risk_score,
                    risk_level=evaluation.risk_level.value,
                    reasons=evaluation.reasons,
                )

            return inserted

        except Exception as e:
            logger.error("Audit logging failure for request '%s': %s", request.request_id, e)
            raise AuditLoggingError(f"Failed to record audit event for request '{request.request_id}': {e}") from e
