"""Unit test cases for the passwords module."""

import pytest

from app.services.passwords import (
    hash_password,
    is_password_hash,
    needs_rehash,
    verify_dummy_password,
    verify_password,
)


@pytest.mark.unit
def test_hash_and_verify_password() -> None:
    """Should verify the right password and reject a wrong one."""
    password_hash = hash_password("secret")
    assert "secret" not in password_hash
    assert password_hash.startswith("$argon2id$")
    assert verify_password(password_hash, "secret")
    assert not verify_password(password_hash, "wrong")


@pytest.mark.unit
def test_hash_password_is_salted() -> None:
    """Should give different hashes for the same password."""
    assert hash_password("secret") != hash_password("secret")


@pytest.mark.unit
def test_verify_password_with_invalid_hash() -> None:
    """Should return False, not raise, when the stored value is not a hash."""
    assert not verify_password("secret", "secret")


@pytest.mark.unit
def test_verify_dummy_password() -> None:
    """Should return without raising for any password."""
    verify_dummy_password("anything")


@pytest.mark.unit
def test_needs_rehash() -> None:
    """Should not need a rehash for a hash made with the current parameters."""
    assert not needs_rehash(hash_password("secret"))


@pytest.mark.unit
def test_is_password_hash() -> None:
    """Should tell hashes from plain-text passwords."""
    assert is_password_hash(hash_password("secret"))
    assert not is_password_hash("secret")
    assert not is_password_hash("")
