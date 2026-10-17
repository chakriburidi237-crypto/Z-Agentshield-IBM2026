"""Repository for persisting and querying security events and review tickets.

All operations use parameterized SQL to guarantee protection against SQL injection.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import sqlite3
from typing import Any, Dict, List, Optional
import uuid

from zagentshield.core.enums import ActionCategory, ActionVerdict, RiskLevel
from zagentshield.db.database import Database


class InvalidReviewStateError(ValueError):
    """Raised when an illegal review status transition is attempted."""


# Allowed review statuses
VALID_REVIEW_STATUSES = {"PENDING", "APPROVED", "REJECTED"}
TERMINAL_REVIEW_STATUSES = {"APPROVED", "REJECTED"}


@dataclass
class SecurityEventRecord:
    """Represents a persisted audit trail event."""

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
    parameters_redacted: Dict[str, Any]
    timestamp: str


@dataclass
class ReviewTicketRecord:
    """Represents a human-in-the-loop review queue ticket."""

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


class SecurityRepository:
    """Data access repository for security events and review tickets."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def record_security_event(
        self,
        request_id: str,
        agent_id: str,
        action: str,
        category: str,
        resource: str,
        verdict: str,
        risk_score: float,
        risk_level: str,
        reasons: List[str],
        matched_rule_ids: List[str],
        parameters_redacted: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ) -> bool:
        """Persist a security evaluation event into the audit trail.
        
        Uses INSERT OR IGNORE to ensure idempotency on duplicate request_id.
        Returns True if inserted, False if request_id already exists.
        """
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        params_json = json.dumps(parameters_redacted or {})
        reasons_json = json.dumps(reasons or [])
        rules_json = json.dumps(matched_rule_ids or [])

        sql = """
        INSERT OR IGNORE INTO security_events (
            request_id, agent_id, action, category, resource,
            verdict, risk_score, risk_level, reasons,
            matched_rule_ids, parameters_redacted, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        with self.db.connection() as conn:
            cursor = conn.execute(
                sql,
                (
                    request_id,
                    agent_id,
                    action,
                    category,
                    resource,
                    verdict,
                    risk_score,
                    risk_level,
                    reasons_json,
                    rules_json,
                    params_json,
                    ts,
                ),
            )
            return cursor.rowcount > 0

    def get_security_event(self, request_id: str) -> Optional[SecurityEventRecord]:
        """Fetch a security event by its unique request_id."""
        sql = "SELECT * FROM security_events WHERE request_id = ?;"
        with self.db.connection() as conn:
            row = conn.execute(sql, (request_id,)).fetchone()
            if not row:
                return None
            return self._row_to_event(row)

    def list_security_events(
        self,
        limit: int = 50,
        offset: int = 0,
        verdict: Optional[str] = None,
    ) -> List[SecurityEventRecord]:
        """List audit events with optional verdict filter and pagination."""
        if verdict:
            sql = """
            SELECT * FROM security_events
            WHERE verdict = ?
            ORDER BY id DESC
            LIMIT ? OFFSET ?;
            """
            params = (verdict, limit, offset)
        else:
            sql = """
            SELECT * FROM security_events
            ORDER BY id DESC
            LIMIT ? OFFSET ?;
            """
            params = (limit, offset)  # type: ignore[assignment]

        with self.db.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_event(r) for r in rows]

    def get_agent_recent_events(
        self,
        agent_id: str,
        since_iso: Optional[str] = None,
        limit: int = 200,
    ) -> List[SecurityEventRecord]:
        """Fetch recent security events for a specific agent, ordered newest first."""
        if since_iso:
            sql = """
            SELECT * FROM security_events
            WHERE agent_id = ? AND timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT ?;
            """
            params = (agent_id, since_iso, limit)
        else:
            sql = """
            SELECT * FROM security_events
            WHERE agent_id = ?
            ORDER BY timestamp DESC
            LIMIT ?;
            """
            params = (agent_id, limit)  # type: ignore[assignment]

        with self.db.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_event(r) for r in rows]

    def create_review_ticket(
        self,
        request_id: str,
        agent_id: str,
        action: str,
        category: str,
        resource: str,
        risk_score: float,
        risk_level: str,
        reasons: List[str],
    ) -> ReviewTicketRecord:
        """Create a new human review ticket in PENDING status."""
        ticket_id = f"tkt-{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc).isoformat()
        reasons_json = json.dumps(reasons or [])

        sql = """
        INSERT INTO review_queue (
            ticket_id, request_id, agent_id, action, category,
            resource, risk_score, risk_level, reasons,
            status, reviewer_id, reviewer_notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', NULL, NULL, ?, ?);
        """
        with self.db.connection() as conn:
            conn.execute(
                sql,
                (
                    ticket_id,
                    request_id,
                    agent_id,
                    action,
                    category,
                    resource,
                    risk_score,
                    risk_level,
                    reasons_json,
                    now,
                    now,
                ),
            )

        return ReviewTicketRecord(
            ticket_id=ticket_id,
            request_id=request_id,
            agent_id=agent_id,
            action=action,
            category=category,
            resource=resource,
            risk_score=risk_score,
            risk_level=risk_level,
            reasons=reasons,
            status="PENDING",
            reviewer_id=None,
            reviewer_notes=None,
            created_at=now,
            updated_at=now,
        )

    def get_review_ticket(self, ticket_id: str) -> Optional[ReviewTicketRecord]:
        """Fetch a review ticket by its ticket_id."""
        sql = "SELECT * FROM review_queue WHERE ticket_id = ?;"
        with self.db.connection() as conn:
            row = conn.execute(sql, (ticket_id,)).fetchone()
            if not row:
                return None
            return self._row_to_ticket(row)

    def get_review_ticket_by_request_id(self, request_id: str) -> Optional[ReviewTicketRecord]:
        """Fetch a review ticket by its associated request_id."""
        sql = "SELECT * FROM review_queue WHERE request_id = ?;"
        with self.db.connection() as conn:
            row = conn.execute(sql, (request_id,)).fetchone()
            if not row:
                return None
            return self._row_to_ticket(row)

    def list_pending_reviews(self, limit: int = 50) -> List[ReviewTicketRecord]:
        """List all pending review tickets ordered by creation time."""
        sql = """
        SELECT * FROM review_queue
        WHERE status = 'PENDING'
        ORDER BY created_at ASC
        LIMIT ?;
        """
        with self.db.connection() as conn:
            rows = conn.execute(sql, (limit,)).fetchall()
            return [self._row_to_ticket(r) for r in rows]

    def update_review_status(
        self,
        ticket_id: str,
        new_status: str,
        reviewer_id: str,
        reviewer_notes: Optional[str] = None,
    ) -> bool:
        """Update review status from PENDING to APPROVED or REJECTED.
        
        Enforces state transition integrity. Raises InvalidReviewStateError
        if attempting an illegal transition (e.g. from APPROVED to REJECTED).
        """
        status_upper = new_status.upper().strip()
        if status_upper not in ("APPROVED", "REJECTED"):
            raise InvalidReviewStateError(
                f"Invalid target status '{new_status}'. Allowed transitions are to APPROVED or REJECTED."
            )

        if not reviewer_id or not reviewer_id.strip():
            raise ValueError("reviewer_id must be provided to update review status.")

        current_ticket = self.get_review_ticket(ticket_id)
        if not current_ticket:
            return False

        if current_ticket.status in TERMINAL_REVIEW_STATUSES:
            raise InvalidReviewStateError(
                f"Cannot update ticket '{ticket_id}' from terminal state '{current_ticket.status}' to '{status_upper}'."
            )

        now = datetime.now(timezone.utc).isoformat()
        sql = """
        UPDATE review_queue
        SET status = ?, reviewer_id = ?, reviewer_notes = ?, updated_at = ?
        WHERE ticket_id = ? AND status = 'PENDING';
        """
        with self.db.connection() as conn:
            cursor = conn.execute(
                sql,
                (status_upper, reviewer_id.strip(), reviewer_notes, now, ticket_id),
            )
            return cursor.rowcount > 0

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> SecurityEventRecord:
        """Convert a sqlite3.Row to a SecurityEventRecord."""
        return SecurityEventRecord(
            id=row["id"],
            request_id=row["request_id"],
            agent_id=row["agent_id"],
            action=row["action"],
            category=row["category"],
            resource=row["resource"],
            verdict=row["verdict"],
            risk_score=row["risk_score"],
            risk_level=row["risk_level"],
            reasons=json.loads(row["reasons"]),
            matched_rule_ids=json.loads(row["matched_rule_ids"]),
            parameters_redacted=json.loads(row["parameters_redacted"] or "{}"),
            timestamp=row["timestamp"],
        )

    @staticmethod
    def _row_to_ticket(row: sqlite3.Row) -> ReviewTicketRecord:
        """Convert a sqlite3.Row to a ReviewTicketRecord."""
        return ReviewTicketRecord(
            ticket_id=row["ticket_id"],
            request_id=row["request_id"],
            agent_id=row["agent_id"],
            action=row["action"],
            category=row["category"],
            resource=row["resource"],
            risk_score=row["risk_score"],
            risk_level=row["risk_level"],
            reasons=json.loads(row["reasons"]),
            status=row["status"],
            reviewer_id=row["reviewer_id"],
            reviewer_notes=row["reviewer_notes"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
