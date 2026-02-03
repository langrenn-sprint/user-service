"""Unit test cases for the security module."""

import os

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
