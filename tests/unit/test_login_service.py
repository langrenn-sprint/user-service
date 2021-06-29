"""Unit test cases for the security module."""
import os

import jwt
import pytest

from user_service.models import User
from user_service.services import create_access_token


@pytest.mark.unit
async def test_create_access_token() -> None:
    """Should return a token."""
    user = User(username="test_user", role="test_role")
    token = await create_access_token(user)
    assert token
    assert len(token) > 0
    secret = os.getenv("JWT_SECRET")
    jwt.decode(token, secret, algorithms="HS256")  # type: ignore
