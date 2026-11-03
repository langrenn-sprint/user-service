"""Module for hashing and verifying passwords."""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher()

# Used to spend the same time on a login for an unknown user as for a known user,
# so that response times do not reveal which usernames exist:
_DUMMY_HASH = _hasher.hash("dummy password used for timing only")


def hash_password(password: str) -> str:
    """Return an argon2id hash of the password."""
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Return True if the password matches the hash.

    Returns False for a wrong password, and for a value that is not a valid hash.
    """
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def verify_dummy_password(password: str) -> None:
    """Verify the password against a dummy hash, to equalize response times."""
    verify_password(_DUMMY_HASH, password)


def needs_rehash(password_hash: str) -> bool:
    """Return True if the hash was made with other parameters than the current."""
    return _hasher.check_needs_rehash(password_hash)


def is_password_hash(value: str) -> bool:
    """Return True if the value is an argon2 hash, not a plain-text password."""
    return value.startswith("$argon2")
