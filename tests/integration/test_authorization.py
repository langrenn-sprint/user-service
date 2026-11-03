"""Integration test cases for authentication and authorization."""

import logging
import os
from http import HTTPStatus

import jwt
import pytest
from fastapi.testclient import TestClient

from app import api

# Any endpoint protected by RoleChecker will do:
PROTECTED_URL = "/users"


@pytest.fixture
def client() -> TestClient:
    """Fixture to create a test client for the FastAPI application."""
    return TestClient(api)


def _token(secret: str, exp: int, role: str = "admin") -> str:
    """Create a token with the given secret, expiry and role."""
    payload = {"username": os.getenv("ADMIN_USERNAME"), "exp": exp, "role": role}
    return jwt.encode(payload, secret, "HS256")


@pytest.mark.integration
async def test_no_token(client: TestClient) -> None:
    """Should return 401 Unauthorized."""
    resp = client.get(PROTECTED_URL)
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.headers["WWW-Authenticate"] == "Bearer"
    assert resp.json() == {"detail": "Not authenticated"}


@pytest.mark.integration
async def test_expired_token(client: TestClient) -> None:
    """Should return 401 Unauthorized."""
    token = _token(os.environ["JWT_SECRET"], exp=1)
    resp = client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.headers["WWW-Authenticate"] == "Bearer"
    assert resp.json() == {"detail": "Not authenticated"}


@pytest.mark.integration
async def test_token_with_invalid_signature(client: TestClient) -> None:
    """Should return 401 Unauthorized."""
    token = _token(
        "not_the_right_secret_for_signing_tokens_in_this_test", exp=9999999999
    )
    resp = client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.integration
async def test_undecodable_token(client: TestClient) -> None:
    """Should return 401 Unauthorized."""
    resp = client.get(PROTECTED_URL, headers={"Authorization": "Bearer not-a-jwt"})
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.integration
async def test_token_without_username_claim(client: TestClient) -> None:
    """Should return 401 Unauthorized."""
    payload = {"exp": 9999999999, "role": "admin"}
    token = jwt.encode(payload, os.environ["JWT_SECRET"], "HS256")
    resp = client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.integration
async def test_token_without_role_claim(client: TestClient) -> None:
    """Should return 401 Unauthorized, not 403, for a token without a role."""
    payload = {"username": os.getenv("ADMIN_USERNAME"), "exp": 9999999999}
    token = jwt.encode(payload, os.environ["JWT_SECRET"], "HS256")
    resp = client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.integration
async def test_valid_token_with_insufficient_role(client: TestClient) -> None:
    """Should return 403 Forbidden."""
    token = _token(os.environ["JWT_SECRET"], exp=9999999999, role="event-admin")
    resp = client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.integration
async def test_jwt_secret_not_configured(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Should return 500, not 403, when the server has no JWT_SECRET."""
    token = _token(os.environ["JWT_SECRET"], exp=9999999999)
    monkeypatch.delenv("JWT_SECRET")
    resp = client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    assert resp.json() == {"detail": "Internal Server Error"}


@pytest.mark.integration
async def test_invalid_token_is_logged_without_traceback(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    """Should log a warning without a stack trace for an invalid token."""
    token = _token(os.environ["JWT_SECRET"], exp=1)
    # The "app" logger does not propagate to the root logger, so attach caplog to it:
    app_logger = logging.getLogger("app")
    app_logger.addHandler(caplog.handler)
    try:
        resp = client.get(PROTECTED_URL, headers={"Authorization": f"Bearer {token}"})
    finally:
        app_logger.removeHandler(caplog.handler)
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.headers["WWW-Authenticate"] == "Bearer"

    records = [r for r in caplog.records if r.name == "app.authorization.authorization"]
    assert [r.getMessage() for r in records] == ["Token has expired"]
    assert records[0].levelno == logging.WARNING
    assert records[0].exc_info is None
