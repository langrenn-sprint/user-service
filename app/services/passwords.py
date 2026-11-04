"""Module for hashing and verifying passwords."""

import asyncio
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher()

# Argon2 deliberately takes tens of milliseconds of CPU time, which would block
# the event loop and stall all other requests. Run it in a thread pool instead.
# The pool is small, because every hash or verification uses 64 MiB of memory:
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="argon2")

# Used to spend the same time on a login for an unknown user as for a known user,
# so that response times do not reveal which usernames exist:
_DUMMY_HASH = _hasher.hash("dummy password used for timing only")


async def _run[T](function: Callable[..., T], *args: str) -> T:
    """Run a blocking argon2 function in the thread pool."""
    return await asyncio.get_running_loop().run_in_executor(_executor, function, *args)


def _verify(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


async def hash_password(password: str) -> str:
    """Return an argon2id hash of the password."""
    return await _run(_hasher.hash, password)


async def verify_password(password_hash: str, password: str) -> bool:
    """Return True if the password matches the hash.

    Returns False for a wrong password, and for a value that is not a valid hash.
    """
    return await _run(_verify, password_hash, password)


async def verify_dummy_password(password: str) -> None:
    """Verify the password against a dummy hash, to equalize response times."""
    await verify_password(_DUMMY_HASH, password)


def needs_rehash(password_hash: str) -> bool:
    """Return True if the hash was made with other parameters than the current."""
    return _hasher.check_needs_rehash(password_hash)


def is_password_hash(value: str) -> bool:
    """Return True if the value is an argon2 hash, not a plain-text password."""
    return value.startswith("$argon2")
