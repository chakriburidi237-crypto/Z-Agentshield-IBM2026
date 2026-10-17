"""SQLite database connection and schema manager for Z-AgentShield.

Initializes structured tables for security audit events and human-in-the-loop review tickets.
Uses parameterized queries and transaction safety.
"""

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Generator, Union


SCHEMA_SQL = """
-- Table: security_events (Audit Trail)
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT UNIQUE NOT NULL,
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL,
    category TEXT NOT NULL,
    resource TEXT NOT NULL,
    verdict TEXT NOT NULL,
    risk_score REAL NOT NULL,
    risk_level TEXT NOT NULL,
    reasons TEXT NOT NULL,
    matched_rule_ids TEXT NOT NULL,
    parameters_redacted TEXT,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_security_events_request_id ON security_events(request_id);
CREATE INDEX IF NOT EXISTS idx_security_events_agent_id ON security_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_security_events_verdict ON security_events(verdict);
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);

-- Table: review_queue (Human-in-the-Loop Tickets)
CREATE TABLE IF NOT EXISTS review_queue (
    ticket_id TEXT PRIMARY KEY,
    request_id TEXT UNIQUE NOT NULL,
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL,
    category TEXT NOT NULL,
    resource TEXT NOT NULL,
    risk_score REAL NOT NULL,
    risk_level TEXT NOT NULL,
    reasons TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    reviewer_id TEXT,
    reviewer_notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_review_queue_status ON review_queue(status);
CREATE INDEX IF NOT EXISTS idx_review_queue_created_at ON review_queue(created_at);
"""


class Database:
    """Manages SQLite database connections, transactions, and schema setup."""

    def __init__(self, db_path: Union[str, Path] = "data/zagentshield.db") -> None:
        self.db_path = str(db_path)
        self._is_memory = self.db_path == ":memory:"

    def get_connection(self) -> sqlite3.Connection:
        """Create and return an optimized SQLite connection."""
        if not self._is_memory:
            # Ensure parent directories exist
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        if not self._is_memory:
            conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for transactional connection management."""
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        """Initialize the database schema (tables and indexes) idempotently."""
        with self.connection() as conn:
            conn.executescript(SCHEMA_SQL)
