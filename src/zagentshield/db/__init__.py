"""Database module for Z-AgentShield.

Exposes the SQLite database manager, repository layer, and domain records.
"""

from zagentshield.db.database import Database
from zagentshield.db.repository import (
    InvalidReviewStateError,
    ReviewTicketRecord,
    SecurityEventRecord,
    SecurityRepository,
)

__all__ = [
    "Database",
    "SecurityRepository",
    "SecurityEventRecord",
    "ReviewTicketRecord",
    "InvalidReviewStateError",
]
