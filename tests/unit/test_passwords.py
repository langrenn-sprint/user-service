"""Unit test cases for the passwords module."""

import threading

import pytest

from app.services import passwords
from app.services.passwords import (
    hash_password,
    is_password_hash,
    needs_rehash,
    verify_dummy_password,
    verify_password,
)


@pytest.mark.unit
async def test_hash_and_verify_password() -> None:
    """Should verify the right password and reject a wrong one."""
    password_hash = await hash_password("secret")
    assert "secret" not in password_hash
    assert password_hash.startswith("$argon2id$")
    assert await verify_password(password_hash, "secret")
    assert not await verify_password(password_hash, "wrong")


@pytest.mark.unit
async def test_hash_password_is_salted() -> None:
    """Should give different hashes for the same password."""
    assert await hash_password("secret") != await hash_password("secret")


@pytest.mark.unit
async def test_verify_password_with_invalid_hash() -> None:
    """Should return False, not raise, when the stored value is not a hash."""
    assert not await verify_password("secret", "secret")


@pytest.mark.unit
async def test_verify_dummy_password() -> None:
    """Should return without raising for any password."""
    await verify_dummy_password("anything")


@pytest.mark.unit
async def test_needs_rehash() -> None:
    """Should not need a rehash for a hash made with the current parameters."""
    assert not needs_rehash(await hash_password("secret"))


@pytest.mark.unit
async def test_is_password_hash() -> None:
    """Should tell hashes from plain-text passwords."""
    assert is_password_hash(await hash_password("secret"))
    assert not is_password_hash("secret")
    assert not is_password_hash("")


@pytest.mark.unit
async def test_is_password_hash_rejects_lookalike_plaintext() -> None:
    """Should treat a plain-text password that only resembles a hash as plain text."""
    password_hash = await hash_password("secret")
    assert not is_password_hash("$argon2-my-password")
    assert not is_password_hash("$argon2id$")
    assert not is_password_hash(password_hash.rsplit("$", 1)[0])  # no hash part
    assert not is_password_hash(password_hash + "\n")
    assert not is_password_hash(" " + password_hash)


@pytest.mark.unit
async def test_argon2_runs_in_thread_pool() -> None:
    """Should run argon2 work in the bounded thread pool, not on the event loop."""
    thread_name = await passwords._run(lambda: threading.current_thread().name)  # noqa: SLF001
    assert thread_name.startswith("argon2")
    assert thread_name != threading.current_thread().name
