"""Unit test cases for the security module."""

import os
import time

import jwt
import pytest
from pydantic import SecretStr

from app.models import Role, User
from app.services import create_access_token


@pytest.mark.unit
async def test_create_access_token() -> None:
    """Should return a token."""
    user = User(
        username="test_user", role=Role.ADMIN, password=SecretStr("test_password")
    )
    token = await create_access_token(user)
    assert token
    assert len(token) > 0
    secret = os.getenv("JWT_SECRET")
    jwt.decode(token, secret, algorithms=["HS256"])


@pytest.mark.unit
async def test_create_access_token_sets_auth_time_to_now() -> None:
    """Should set auth_time to the time of login when not given."""
    user = User(
        username="test_user", role=Role.ADMIN, password=SecretStr("test_password")
    )
    before = int(time.time())
    token = await create_access_token(user)
    claims = jwt.decode(token, os.getenv("JWT_SECRET"), algorithms=["HS256"])
    assert before <= claims["auth_time"] <= int(time.time())


@pytest.mark.unit
async def test_create_access_token_keeps_given_auth_time() -> None:
    """Should keep the given auth_time, e.g. when renewing."""
    user = User(
        username="test_user", role=Role.ADMIN, password=SecretStr("test_password")
    )
    token = await create_access_token(user, auth_time=1_000_000)
    claims = jwt.decode(token, os.getenv("JWT_SECRET"), algorithms=["HS256"])
    assert claims["auth_time"] == 1_000_000  # noqa: PLR2004
