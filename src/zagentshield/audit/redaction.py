"""Sensitive data redaction module for Z-AgentShield.

Sanitizes payloads, parameters, and logs before persistence to prevent credentials,
API tokens, private keys, and PII from being stored in audit logs.

NOTE: Pattern-based and heuristic dictionary redaction is a defense-in-depth mechanism.
It reduces exposure risks but cannot guarantee 100% detection of arbitrary secrets.
Organizations should enforce data minimization at the agent boundary.
"""

import copy
import re
from typing import Any, Dict, List, Set, Union

REDACTED_PLACEHOLDER = "[REDACTED]"
REDACTED_JWT_PLACEHOLDER = "[REDACTED_JWT]"
REDACTED_KEY_PLACEHOLDER = "[REDACTED_PRIVATE_KEY]"
REDACTED_CARD_PLACEHOLDER = "[REDACTED_CARD]"

# Exact or substring keywords indicating a sensitive dictionary key
SENSITIVE_KEY_PATTERNS: Set[str] = {
    "password",
    "passwd",
    "secret",
    "access_token",
    "refresh_token",
    "private_key",
    "authorization",
    "auth",
    "api_key",
    "apikey",
    "token",
    "credential",
    "credentials",
    "client_secret",
    "session_id",
    "cvv",
    "ssn",
}

# Regex patterns for detecting inline secrets in arbitrary strings
INLINE_SECRET_PATTERNS = [
    # PEM Private Keys
    (
        re.compile(r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]+PRIVATE KEY-----"),
        REDACTED_KEY_PLACEHOLDER,
    ),
    # Bearer authorization headers
    (
        re.compile(r"(?i)\bBearer\s+[a-zA-Z0-9_\-\.\~+/=]{8,}"),
        "Bearer [REDACTED]",
    ),
    # JSON Web Tokens (JWT)
    (
        re.compile(r"\beyJ[a-zA-Z0-9_-]{8,}\.eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]+\b"),
        REDACTED_JWT_PLACEHOLDER,
    ),
    # Credit Card Numbers (13-16 digits formatted with spaces/hyphens)
    (
        re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        REDACTED_CARD_PLACEHOLDER,
    ),
    # Typical API keys starting with sk_, pk_, api_, key-
    (
        re.compile(r"\b(?:sk|pk|api|key)[-_][a-zA-Z0-9]{16,}\b"),
        REDACTED_PLACEHOLDER,
    ),
]


def is_sensitive_key(key: str) -> bool:
    """Check if a dictionary key name suggests sensitive content."""
    if not isinstance(key, str):
        return False
    key_lower = key.lower()
    return any(pattern in key_lower for pattern in SENSITIVE_KEY_PATTERNS)


def redact_string(text: str) -> str:
    """Sanitize sensitive patterns from a string without mutating original value."""
    if not isinstance(text, str):
        return text

    sanitized = text
    for pattern, replacement in INLINE_SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def redact_sensitive_data(data: Any) -> Any:
    """Recursively redact sensitive keys and inline secret strings from data structures.
    
    Ensures caller's input object is never mutated by returning a deep-copied/new structure.
    
    Args:
        data: Arbitrary Python object (dict, list, tuple, set, primitive).
        
    Returns:
        A sanitized copy with sensitive fields masked.
    """
    if data is None:
        return None

    if isinstance(data, dict):
        sanitized_dict: Dict[str, Any] = {}
        for k, v in data.items():
            str_key = str(k)
            if is_sensitive_key(str_key):
                sanitized_dict[str_key] = REDACTED_PLACEHOLDER
            else:
                sanitized_dict[str_key] = redact_sensitive_data(v)
        return sanitized_dict

    elif isinstance(data, list):
        return [redact_sensitive_data(item) for item in data]

    elif isinstance(data, tuple):
        return tuple(redact_sensitive_data(item) for item in data)

    elif isinstance(data, set):
        return {redact_sensitive_data(item) for item in data}

    elif isinstance(data, str):
        return redact_string(data)

    elif isinstance(data, (int, float, bool)):
        return data

    # For other objects, convert to string safely and sanitize
    try:
        return redact_string(str(data))
    except Exception:
        return "[UNSERIALIZABLE_OBJECT]"
