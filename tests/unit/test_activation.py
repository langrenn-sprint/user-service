"""Unit test cases for activation codes and what is shown about a user."""

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.services import user_info
from app.services.activation import hash_activation_code, new_activation_code


@pytest.mark.unit
def test_new_activation_code() -> None:
    """Should give a long random code, its hash, and an expiry in 48 hours."""
    code, code_hash, expires = new_activation_code()
    other_code, _, _ = new_activation_code()

    assert len(code) >= 43  # 32 random bytes  # noqa: PLR2004
    assert code != other_code
    assert code_hash == hashlib.sha256(code.encode()).hexdigest()
    assert code not in code_hash
    expected = datetime.now(UTC) + timedelta(hours=48)
    assert abs(expires - expected) < timedelta(seconds=5)


@pytest.mark.unit
def test_hash_activation_code() -> None:
    """Should give the same hash for the same code."""
    assert hash_activation_code("abc") == hash_activation_code("abc")
    assert hash_activation_code("abc") != hash_activation_code("abd")


@pytest.mark.unit
def test_user_info_not_activated() -> None:
    """Should show a user without password as not activated, with the expiry."""
    expires = datetime(2026, 11, 8, 12, 0)  # noqa: DTZ001 - naive UTC, as from MongoDB
    document = {
        "id": uuid4(),
        "username": "ny@example.com",
        "role": "event-admin",
        "password": None,
        "activation_code_hash": "hash",
        "activation_expires": expires,
    }

    info = user_info(document)

    assert info.activated is False
    assert info.activation_expires == expires.replace(tzinfo=UTC)
    assert "activation_code_hash" not in info.model_dump()


@pytest.mark.unit
def test_user_info_activated() -> None:
    """Should show a user with password as activated, without expiry."""
    document = {
        "id": uuid4(),
        "username": "aktiv@example.com",
        "role": "admin",
        "password": "$argon2id$hash",
    }

    info = user_info(document)

    assert info.activated is True
    assert info.activation_expires is None
    assert "password" not in info.model_dump()


@pytest.mark.unit
def test_activation_code_expiry_in_milliseconds() -> None:
    """Should round the expiry to milliseconds, as MongoDB stores it."""
    _, _, expires = new_activation_code()
    assert expires.microsecond % 1000 == 0
