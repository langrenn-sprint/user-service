"""Module for activation codes, used by users to set their own password."""

import hashlib
import os
import secrets
from datetime import UTC, datetime, timedelta

# How long an activation code is valid. An empty value means the default, as
# docker-compose passes unset variables as "":
ACTIVATION_CODE_TTL_HOURS = int(os.getenv("ACTIVATION_CODE_TTL_HOURS") or "48")


def new_activation_code() -> tuple[str, str, datetime]:
    """Return a new random code, the hash to store, and when it expires.

    Only the hash is stored, so the code cannot be read from the database. The
    code has 256 bits of randomness, so a fast hash is enough: it cannot be
    guessed, unlike a password.
    """
    code = secrets.token_urlsafe(32)
    expires = datetime.now(UTC) + timedelta(hours=ACTIVATION_CODE_TTL_HOURS)
    # MongoDB stores milliseconds; round so the stored time is the one returned:
    expires = expires.replace(microsecond=expires.microsecond // 1000 * 1000)
    return code, hash_activation_code(code), expires


def hash_activation_code(code: str) -> str:
    """Return the hash that is stored for an activation code."""
    return hashlib.sha256(code.encode()).hexdigest()
