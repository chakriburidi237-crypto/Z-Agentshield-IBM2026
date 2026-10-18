"""Generate one local demo account record without writing credentials to disk."""

import getpass
import json
import secrets
import sys

from zagentshield.auth import VALID_ROLES, create_password_record


def main() -> int:
    username = input("Local account username: ").strip()
    if not username or len(username) > 128:
        print("Username must contain between 1 and 128 characters.", file=sys.stderr)
        return 2

    print("Available roles: " + ", ".join(sorted(VALID_ROLES)))
    role = input("Role: ").strip().upper()
    if role not in VALID_ROLES:
        print("Select SOC_ANALYST or SECURITY_ADMIN.", file=sys.stderr)
        return 2

    password = getpass.getpass("Account password (minimum 12 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        print("Passwords do not match.", file=sys.stderr)
        return 2

    try:
        record = {
            "username": username,
            "role": role,
            **create_password_record(password),
        }
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    users_json = json.dumps([record], separators=(",", ":"))
    signing_secret = secrets.token_urlsafe(48)
    print("\nCopy these values to your ignored .env file:")
    print(f"AUTH_USERS_JSON={users_json}")
    print(f"AUTH_TOKEN_SECRET={signing_secret}")
    print("AUTH_TOKEN_LIFETIME_SECONDS=900")
    print("\nKeep the signing secret private. This local account setup is not a production identity provider.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
