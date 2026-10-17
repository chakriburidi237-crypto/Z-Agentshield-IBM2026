"""FastAPI Security Gateway for Z-AgentShield.

Exposes the existing security workflow over HTTP with strict input validation,
fail-closed error handling, and explicit authentication boundaries.

Security invariants enforced at this layer:
- BLOCK never executes a callback.
- REVIEW never executes a callback before explicit human approval.
- Audit failures produce fail-closed BLOCK responses (never implicit ALLOW).
- Client-supplied identity/permission fields cannot grant authorization.
- Stack traces, secrets, and raw parameters are never returned to callers.
"""

from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from zagentshield.anomalies.detector import AnomalyConfig, AnomalyDetector
from zagentshield.audit.logger import AuditLogger
from zagentshield.config import get_settings
from zagentshield.core.enums import ActionVerdict, RiskLevel
from zagentshield.core.models import AgentRequest, SecurityEvaluation
from zagentshield.core.schemas import HealthResponse, InterceptRequest, InterceptResponse
from zagentshield.db.database import Database
from zagentshield.db.repository import (
    InvalidReviewStateError,
    ReviewTicketRecord,
    SecurityEventRecord,
    SecurityRepository,
)
from zagentshield.policies.engine import PolicyEngine

logger = logging.getLogger("zagentshield.api")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50
API_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Request / Response Pydantic models for API layer
# ---------------------------------------------------------------------------


class ReviewDecisionRequest(BaseModel):
    """Body for POST /api/v1/reviews/{ticket_id}/decision."""

    decision: str = Field(
        ...,
        description="Must be 'APPROVED' or 'REJECTED'.",
    )
    reviewer_notes: Optional[str] = Field(
        default=None,
        max_length=2048,
        description="Optional notes recorded by the human reviewer.",
    )

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "decision": "APPROVED",
                "reviewer_notes": "Authorized after compliance check."
            }
        },
    )


class ReviewTicketResponse(BaseModel):
    """Sanitized review ticket representation returned to API callers."""

    ticket_id: str
    request_id: str
    agent_id: str
    action: str
    category: str
    resource: str
    risk_score: float
    risk_level: str
    reasons: List[str]
    status: str
    reviewer_id: Optional[str]
    reviewer_notes: Optional[str]
    created_at: str
    updated_at: str

    @classmethod
    def from_record(cls, record: ReviewTicketRecord) -> "ReviewTicketResponse":
        return cls(**record.__dict__)


class AuditEventResponse(BaseModel):
    """Sanitized audit event representation returned to API callers.

    parameters_redacted is intentionally excluded; callers receive counts and
    verdicts only.
    """

    id: int
    request_id: str
    agent_id: str
    action: str
    category: str
    resource: str
    verdict: str
    risk_score: float
    risk_level: str
    reasons: List[str]
    matched_rule_ids: List[str]
    timestamp: str

    @classmethod
    def from_record(cls, record: SecurityEventRecord) -> "AuditEventResponse":
        return cls(
            id=record.id,
            request_id=record.request_id,
            agent_id=record.agent_id,
            action=record.action,
            category=record.category,
            resource=record.resource,
            verdict=record.verdict,
            risk_score=record.risk_score,
            risk_level=record.risk_level,
            reasons=record.reasons,
            matched_rule_ids=record.matched_rule_ids,
            timestamp=record.timestamp,
        )


class ErrorResponse(BaseModel):
    """Uniform error envelope. Never exposes internal detail."""

    error: str
    code: str


class InterceptResponseWithTicket(InterceptResponse):
    """Extended intercept response that may include a review ticket_id."""

    ticket_id: Optional[str] = Field(
        default=None,
        description="Review ticket identifier when verdict is REVIEW.",
    )


# ---------------------------------------------------------------------------
# Authentication dependency
# ---------------------------------------------------------------------------
# Z-AgentShield does not implement a production identity provider. Privileged
# endpoints (review decisions, audit logs) require the caller to supply a
# trusted reviewer identity via the X-Reviewer-Id HTTP header.
#
# IMPORTANT SECURITY NOTE:
#   This header-based mechanism is an integration boundary, NOT a cryptographic
#   authentication system. In production, the gateway MUST be placed behind a
#   reverse proxy or API gateway that validates identity tokens and injects this
#   header from a verified, server-side source. The client MUST NOT be trusted
#   to supply its own identity claims directly.
#
#   The server NEVER accepts reviewer_id, is_admin, or permission flags from
#   the request JSON body. Only the server-injected header is consulted.


def require_reviewer_identity(
    x_reviewer_id: Optional[str] = Header(default=None, alias="X-Reviewer-Id"),
) -> str:
    """Dependency that fails closed if no reviewer identity header is present.

    In production, set this header from a verified server-side auth token.
    This dependency must NOT be bypassed by client-supplied JSON fields.
    """
    if not x_reviewer_id or not x_reviewer_id.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Reviewer identity required. Set X-Reviewer-Id from a trusted authentication source.", "code": "UNAUTHENTICATED"},
        )
    reviewer = x_reviewer_id.strip()
    # Reject suspiciously long or malformed reviewer identities
    if len(reviewer) > 128 or not reviewer.isprintable():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Invalid reviewer identity format.", "code": "INVALID_REVIEWER_ID"},
        )
    return reviewer


# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------


class AppServices:
    """Container for all injected application services.

    Centralises lifetime management; tests inject mocked versions through
    create_app(services=...).
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        repository: SecurityRepository,
        audit_logger: AuditLogger,
        anomaly_detector: Optional[AnomalyDetector] = None,
        resource_classifier: Optional[Callable[[AgentRequest], bool]] = None,
    ) -> None:
        self.policy_engine = policy_engine
        self.repository = repository
        self.audit_logger = audit_logger
        self.anomaly_detector = anomaly_detector
        self.resource_classifier = resource_classifier


def _apply_resource_classification_gate(
    services: AppServices,
    request: AgentRequest,
    evaluation: SecurityEvaluation,
) -> SecurityEvaluation:
    """Convert policy ALLOW to BLOCK unless a trusted classifier verifies it."""
    if evaluation.verdict != ActionVerdict.ALLOW:
        return evaluation

    if services.resource_classifier is None:
        reason = (
            "Trusted resource classification is not configured; "
            "the action was denied."
        )
    else:
        try:
            if services.resource_classifier(request):
                return evaluation
        except Exception:
            logger.exception(
                "Trusted resource classification failed for request '%s'",
                request.request_id,
            )
        reason = (
            "The trusted resource classifier did not verify this resource; "
            "the action was denied."
        )

    return SecurityEvaluation(
        request_id=evaluation.request_id,
        verdict=ActionVerdict.BLOCK,
        risk_score=evaluation.risk_score,
        risk_level=evaluation.risk_level,
        reasons=[*evaluation.reasons, reason],
        matched_rule_ids=evaluation.matched_rule_ids,
        timestamp=evaluation.timestamp,
    )


def build_default_services(
    db_path: str = "data/zagentshield.db",
    policy_path: str = "config/policies.yaml",
    risk_threshold_review: float = 40.0,
    risk_threshold_block: float = 75.0,
) -> AppServices:
    """Build the default production service graph."""
    db = Database(db_path)
    db.init_db()
    repo = SecurityRepository(db)
    audit = AuditLogger(repo)
    engine = PolicyEngine.from_yaml_file(
        policy_path,
        risk_threshold_review=risk_threshold_review,
        risk_threshold_block=risk_threshold_block,
    )
    detector = AnomalyDetector(config=AnomalyConfig(), repository=repo)
    return AppServices(
        policy_engine=engine,
        repository=repo,
        audit_logger=audit,
        anomaly_detector=detector,
    )


def create_app(services: Optional[AppServices] = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        services: Optional pre-built AppServices for testing. When None, the
                  production service graph is constructed on first request via
                  lifespan. Tests should always supply injected services.
    """
    settings = get_settings()
    docs_enabled = settings.app_env.strip().lower() == "development"
    docs_url = "/docs" if docs_enabled else None
    openapi_url = "/openapi.json" if docs_enabled else None
    app = FastAPI(
        title="Z-AgentShield Security Gateway",
        description=(
            "Real-Time Security Layer for Enterprise AI Agents. "
            "Intercepts, evaluates, and gates agent actions via policy rules, "
            "risk scoring, and behavioral anomaly detection."
        ),
        version=API_VERSION,
        # Interactive documentation and its schema exist only in development.
        docs_url=docs_url,
        redoc_url=None,
        openapi_url=openapi_url,
    )

    # Store services in app state for dependency injection
    app.state.services = services

    # -----------------------------------------------------------------------
    # Global error handlers — never expose internal detail
    # -----------------------------------------------------------------------

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Pydantic messages can include attacker-supplied values; keep errors generic.
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": "Request validation failed.", "code": "VALIDATION_ERROR"},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        logger.error("Unhandled gateway exception on %s: %s", request.url.path, exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "Internal server error.", "code": "INTERNAL_ERROR"},
        )

    # -----------------------------------------------------------------------
    # Dependency: resolve services from app state
    # -----------------------------------------------------------------------

    def get_services(request: Request) -> AppServices:
        svc = request.app.state.services
        if svc is None:
            # Lazy init for production (not used in tests)
            settings = get_settings()
            svc = build_default_services(
                db_path=settings.database_path,
                policy_path=settings.policy_config_path,
                risk_threshold_review=settings.risk_threshold_review,
                risk_threshold_block=settings.risk_threshold_block,
            )
            request.app.state.services = svc
        return svc

    # -----------------------------------------------------------------------
    # Route: GET /
    # -----------------------------------------------------------------------

    @app.get(
        "/",
        summary="Service root",
        tags=["System"],
    )
    async def root() -> Dict[str, Any]:
        """Return minimal service identity and documentation links."""
        return {
            "service": "Z-AgentShield Security Gateway",
            "version": API_VERSION,
            "status": "active",
            "docs": docs_url,
            "health": "/health",
        }

    # -----------------------------------------------------------------------
    # Route: GET /health
    # -----------------------------------------------------------------------

    @app.get(
        "/health",
        response_model=HealthResponse,
        summary="Health check",
        tags=["System"],
    )
    async def health() -> HealthResponse:
        """Return minimal health status. Does not expose config or secrets."""
        return HealthResponse(
            status="ok",
            version=API_VERSION,
            timestamp=datetime.now(timezone.utc),
        )

    # -----------------------------------------------------------------------
    # Route: POST /api/v1/intercept
    # -----------------------------------------------------------------------

    @app.post(
        "/api/v1/intercept",
        response_model=InterceptResponseWithTicket,
        status_code=status.HTTP_200_OK,
        summary="Intercept and evaluate an agent action",
        tags=["Interception"],
    )
    async def intercept(
        body: InterceptRequest,
        svc: AppServices = Depends(get_services),
    ) -> InterceptResponseWithTicket:
        """Evaluate an intercepted agent action request.

        Security guarantees:
        - claimed_permissions in the request body are never trusted for authorization.
        - BLOCK and REVIEW never invoke any callback.
        - Audit failure causes a fail-closed BLOCK (never implicit ALLOW).
        - Sensitive parameters are redacted before persistence.
        - Stack traces are never returned to callers.
        """
        agent_request = body.to_agent_request()

        # Step 1: Idempotency — check for duplicate request_id
        existing = svc.repository.get_security_event(agent_request.request_id)
        if existing is not None:
            existing_eval = _build_evaluation_from_event(existing)
            if existing.verdict == ActionVerdict.ALLOW.value:
                same_resource_request = (
                    existing.agent_id == agent_request.agent_id
                    and existing.action == agent_request.action
                    and existing.category == agent_request.category.value
                    and existing.resource == agent_request.resource
                )
                if same_resource_request:
                    existing_eval = _apply_resource_classification_gate(
                        svc,
                        agent_request,
                        existing_eval,
                    )
                else:
                    existing_eval = SecurityEvaluation(
                        request_id=existing_eval.request_id,
                        verdict=ActionVerdict.BLOCK,
                        risk_score=existing_eval.risk_score,
                        risk_level=existing_eval.risk_level,
                        reasons=[
                            *existing_eval.reasons,
                            "The repeated request identifier did not match the "
                            "recorded resource request; the action was denied.",
                        ],
                        matched_rule_ids=existing_eval.matched_rule_ids,
                        timestamp=existing_eval.timestamp,
                    )
            base = InterceptResponse.from_evaluation(existing_eval)
            return InterceptResponseWithTicket(
                **base.model_dump(),
                ticket_id=_get_ticket_id(svc, agent_request.request_id),
            )

        # Step 2: Anomaly detection (optional; fail-safe)
        anomaly_assessment = None
        if svc.anomaly_detector is not None:
            try:
                anomaly_assessment = svc.anomaly_detector.detect_anomalies(agent_request)
            except Exception as e:
                logger.error("Anomaly detection failed for request '%s': %s", agent_request.request_id, e)
                # Continue without anomaly — evaluation still happens

        # Step 3: Policy evaluation (fail-closed on exception)
        try:
            evaluation = svc.policy_engine.evaluate(
                request=agent_request,
                trusted_permissions=None,  # No trusted creds in this gateway path
                anomaly_assessment=anomaly_assessment,
            )
        except Exception as e:
            logger.error("Policy engine error for request '%s': %s", agent_request.request_id, e)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"error": "Policy evaluation failed. Request denied.", "code": "POLICY_ERROR"},
            )

        evaluation = _apply_resource_classification_gate(
            svc,
            agent_request,
            evaluation,
        )

        # Step 4: Audit persistence (fail-closed on failure)
        try:
            svc.audit_logger.log_evaluation(agent_request, evaluation)
        except Exception as e:
            logger.error("Audit logging failed for request '%s': %s", agent_request.request_id, e)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"error": "Audit logging failed. Request denied for integrity.", "code": "AUDIT_ERROR"},
            )

        # Step 5: Retrieve review ticket_id if REVIEW verdict
        ticket_id = None
        if evaluation.verdict == ActionVerdict.REVIEW:
            ticket_id = _get_ticket_id(svc, agent_request.request_id)

        base = InterceptResponse.from_evaluation(evaluation)
        return InterceptResponseWithTicket(**base.model_dump(), ticket_id=ticket_id)

    # -----------------------------------------------------------------------
    # Route: GET /api/v1/decisions/{request_id}
    # -----------------------------------------------------------------------

    @app.get(
        "/api/v1/decisions/{request_id}",
        response_model=AuditEventResponse,
        summary="Retrieve a recorded decision",
        tags=["Decisions"],
    )
    async def get_decision(
        request_id: str,
        svc: AppServices = Depends(get_services),
    ) -> AuditEventResponse:
        """Retrieve a previously evaluated and recorded decision by request_id.

        Returns 404 when the request_id has no recorded decision.
        Raw parameters are never returned (only redacted metadata).
        """
        if not request_id or len(request_id) > 128:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "Invalid request_id.", "code": "INVALID_REQUEST_ID"},
            )
        event = svc.repository.get_security_event(request_id)
        if event is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": f"No decision found for request_id '{request_id}'.", "code": "NOT_FOUND"},
            )
        return AuditEventResponse.from_record(event)

    # -----------------------------------------------------------------------
    # Route: GET /api/v1/reviews
    # -----------------------------------------------------------------------

    @app.get(
        "/api/v1/reviews",
        response_model=List[ReviewTicketResponse],
        summary="List review tickets",
        tags=["Reviews"],
    )
    async def list_reviews(
        limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
        svc: AppServices = Depends(get_services),
    ) -> List[ReviewTicketResponse]:
        """Return pending review tickets with bounded pagination.

        Defaults to PENDING status. Limit is bounded to prevent unbounded reads.
        """
        tickets = svc.repository.list_pending_reviews(limit=limit)
        return [ReviewTicketResponse.from_record(t) for t in tickets]

    # -----------------------------------------------------------------------
    # Route: POST /api/v1/reviews/{ticket_id}/decision
    # -----------------------------------------------------------------------

    @app.post(
        "/api/v1/reviews/{ticket_id}/decision",
        response_model=ReviewTicketResponse,
        summary="Approve or reject a review ticket",
        tags=["Reviews"],
    )
    async def decide_review(
        ticket_id: str,
        body: ReviewDecisionRequest,
        reviewer_id: str = Depends(require_reviewer_identity),
        svc: AppServices = Depends(get_services),
    ) -> ReviewTicketResponse:
        """Record an explicit APPROVED or REJECTED decision on a review ticket.

        Security guarantees:
        - reviewer_id is sourced from X-Reviewer-Id header only — never from the body.
        - Invalid state transitions (e.g. re-deciding an APPROVED ticket) are rejected.
        - Approving a ticket does NOT automatically execute the protected operation.
        - Client-supplied permission claims cannot influence this endpoint.
        """
        if not ticket_id or len(ticket_id) > 128:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "Invalid ticket_id.", "code": "INVALID_TICKET_ID"},
            )

        # Validate the decision value before touching the DB
        decision_upper = body.decision.upper().strip()
        if decision_upper not in ("APPROVED", "REJECTED"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": f"Invalid decision '{body.decision}'. Must be 'APPROVED' or 'REJECTED'.",
                    "code": "INVALID_DECISION",
                },
            )

        # Verify ticket exists
        ticket = svc.repository.get_review_ticket(ticket_id)
        if ticket is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": f"Review ticket '{ticket_id}' not found.", "code": "NOT_FOUND"},
            )

        # Attempt status update — repository enforces state-machine invariants
        try:
            updated = svc.repository.update_review_status(
                ticket_id=ticket_id,
                new_status=decision_upper,
                reviewer_id=reviewer_id,  # From trusted header, NOT from body
                reviewer_notes=body.reviewer_notes,
            )
        except InvalidReviewStateError as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": str(e), "code": "INVALID_STATE_TRANSITION"},
            )
        except Exception as e:
            logger.error("Review update failed for ticket '%s': %s", ticket_id, e)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"error": "Failed to update review ticket.", "code": "UPDATE_ERROR"},
            )

        if not updated:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "Ticket could not be updated (may already be in a terminal state).", "code": "UPDATE_CONFLICT"},
            )

        updated_ticket = svc.repository.get_review_ticket(ticket_id)
        if updated_ticket is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"error": "Failed to retrieve updated ticket.", "code": "INTERNAL_ERROR"},
            )
        return ReviewTicketResponse.from_record(updated_ticket)

    # -----------------------------------------------------------------------
    # Route: GET /api/v1/audit/logs
    # -----------------------------------------------------------------------

    @app.get(
        "/api/v1/audit/logs",
        response_model=List[AuditEventResponse],
        summary="List sanitized audit records",
        tags=["Audit"],
    )
    async def audit_logs(
        limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
        offset: int = Query(default=0, ge=0),
        verdict: Optional[str] = Query(default=None),
        reviewer_id: str = Depends(require_reviewer_identity),
        svc: AppServices = Depends(get_services),
    ) -> List[AuditEventResponse]:
        """Return sanitized audit records.

        Protected: requires X-Reviewer-Id header from a trusted authentication source.
        Pagination is bounded. Raw parameters are never returned.
        """
        # Validate optional verdict filter
        valid_verdicts = {"ALLOW", "REVIEW", "BLOCK"}
        if verdict is not None and verdict.upper() not in valid_verdicts:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": f"Invalid verdict filter '{verdict}'. Must be one of: ALLOW, REVIEW, BLOCK.",
                    "code": "INVALID_FILTER",
                },
            )

        events = svc.repository.list_security_events(
            limit=limit,
            offset=offset,
            verdict=verdict.upper() if verdict else None,
        )
        return [AuditEventResponse.from_record(e) for e in events]

    return app


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_ticket_id(svc: AppServices, request_id: str) -> Optional[str]:
    """Retrieve a review ticket ID, allowing repository failures to fail the request."""
    ticket = svc.repository.get_review_ticket_by_request_id(request_id)
    return ticket.ticket_id if ticket else None


def _build_evaluation_from_event(event: SecurityEventRecord):
    """Reconstruct a minimal SecurityEvaluation from a stored audit event."""
    from zagentshield.core.models import SecurityEvaluation
    from zagentshield.core.enums import ActionVerdict, RiskLevel
    from datetime import datetime, timezone

    return SecurityEvaluation(
        request_id=event.request_id,
        verdict=ActionVerdict(event.verdict),
        risk_score=event.risk_score,
        risk_level=RiskLevel(event.risk_level),
        reasons=event.reasons or ["Previously recorded decision."],
        matched_rule_ids=event.matched_rule_ids or [],
        timestamp=datetime.now(timezone.utc),
    )


# Uvicorn entry point; services are initialized lazily on the first request.
app = create_app()
