"""Local, server-configured authentication for the gateway demo."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
import time
from typing import Any


PBKDF2_ITERATIONS = 600_000
TOKEN_LIFETIME_SECONDS = 900
VALID_ROLES = {"SOC_ANALYST", "SECURITY_ADMIN", "SECURITY_OFFICER", "PLATFORM_ADMIN"}


class AuthenticationError(ValueError):
    """Raised when credentials or an access token are invalid."""


class AuthenticationUnavailable(RuntimeError):
    """Raised when authentication has not been securely configured."""


@dataclass(frozen=True)
class AuthenticatedUser:
    username: str
    role: str


def create_password_record(password: str) -> dict[str, str]:
    """Create a PBKDF2-SHA256 password record suitable for server config."""
    if len(password) < 12:
        raise ValueError("Passwords must contain at least 12 characters.")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return {
        "salt": base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
        "password_hash": base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="),
    }


def _decode_b64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class LocalAuthManager:
    """Validates environment-configured password hashes and signed sessions."""

    def __init__(
        self,
        users_json: str | None,
        signing_secret: str | None,
        token_lifetime_seconds: int = TOKEN_LIFETIME_SECONDS,
    ) -> None:
        if not 60 <= token_lifetime_seconds <= 86_400:
            raise ValueError("Token lifetime must be between 60 and 86400 seconds.")
        self.token_lifetime_seconds = token_lifetime_seconds
        self._secret = signing_secret.encode("utf-8") if signing_secret else None
        if self._secret is not None and len(self._secret) < 32:
            raise ValueError("The authentication signing secret must be 32+ bytes.")
        self._users: dict[str, dict[str, Any]] = {}
        if users_json:
            try:
                configured = json.loads(users_json)
            except json.JSONDecodeError as exc:
                raise ValueError("Configured authentication users are invalid JSON.") from exc
            if not isinstance(configured, list):
                raise ValueError("Configured authentication users must be a JSON list.")
            for user in configured:
                if not isinstance(user, dict):
                    raise ValueError("Each configured user must be an object.")
                username = user.get("username")
                role = user.get("role")
                salt = user.get("salt")
                password_hash = user.get("password_hash")
                if (
                    not isinstance(username, str)
                    or not username
                    or len(username) > 128
                    or not isinstance(role, str)
                    or role not in VALID_ROLES
                    or not isinstance(salt, str)
                    or not isinstance(password_hash, str)
                ):
                    raise ValueError("A configured authentication user is malformed.")
                if username in self._users:
                    raise ValueError("Configured usernames must be unique.")
                try:
                    _decode_b64(salt)
                    _decode_b64(password_hash)
                except (ValueError, TypeError) as exc:
                    raise ValueError("A configured password hash is malformed.") from exc
                self._users[username] = user

    @property
    def configured(self) -> bool:
        return bool(self._secret and self._users)

    def login(self, username: str, password: str) -> tuple[str, AuthenticatedUser]:
        if not self.configured:
            raise AuthenticationUnavailable("Authentication is not configured.")
        user = self._users.get(username)
        if user is None:
            # Perform a comparable PBKDF2 operation to reduce username timing leaks.
            hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), b"zagentshield-invalid", PBKDF2_ITERATIONS
            )
            raise AuthenticationError("Invalid username or password.")
        expected = _decode_b64(user["password_hash"])
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            _decode_b64(user["salt"]),
            PBKDF2_ITERATIONS,
        )
        if not hmac.compare_digest(actual, expected):
            raise AuthenticationError("Invalid username or password.")
        identity = AuthenticatedUser(username=username, role=user["role"])
        return self.issue_token(identity), identity

    def issue_token(self, user: AuthenticatedUser) -> str:
        if not self.configured:
            raise AuthenticationUnavailable("Authentication is not configured.")
        claims = {
            "sub": user.username,
            "role": user.role,
            "exp": int(time.time()) + self.token_lifetime_seconds,
        }
        payload = base64.urlsafe_b64encode(
            json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).decode("ascii").rstrip("=")
        signature = hmac.new(
            self._secret, payload.encode("ascii"), hashlib.sha256
        ).digest()
        return f"{payload}.{base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')}"

    def verify_token(self, token: str) -> AuthenticatedUser:
        if not self.configured:
            raise AuthenticationUnavailable("Authentication is not configured.")
        try:
            payload, signature = token.split(".", 1)
            expected = hmac.new(
                self._secret, payload.encode("ascii"), hashlib.sha256
            ).digest()
            if not hmac.compare_digest(expected, _decode_b64(signature)):
                raise AuthenticationError("Invalid access token.")
            claims = json.loads(_decode_b64(payload))
            username = claims["sub"]
            role = claims["role"]
            expires_at = claims["exp"]
            current_user = self._users.get(username)
            if (
                not isinstance(username, str)
                or not isinstance(role, str)
                or role not in VALID_ROLES
                or not isinstance(expires_at, int)
                or expires_at <= int(time.time())
                or current_user is None
                or current_user["role"] != role
            ):
                raise AuthenticationError("Invalid or expired access token.")
            return AuthenticatedUser(username=username, role=role)
        except AuthenticationError:
            raise
        except (ValueError, TypeError, KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthenticationError("Invalid access token.") from exc
