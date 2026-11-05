"""Resource module for token resources."""

import logging
from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.services import LoginService, TokenRenewalError

logger = logging.getLogger(__name__)

router = APIRouter()

bearer_scheme = HTTPBearer(auto_error=False)


def _not_authenticated() -> HTTPException:
    return HTTPException(
        status_code=HTTPStatus.UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post("/token/renew")
async def renew(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Security(bearer_scheme)
    ],
) -> dict:
    """Renew a valid token, returning a new one with full lifetime."""
    if credentials is None:
        raise _not_authenticated()
    try:
        jwt_token = await LoginService.renew(credentials.credentials)
    except TokenRenewalError as e:
        # A routine client error: log one line, without a stack trace.
        logger.warning("Token renewal failed: %s", e)
        raise _not_authenticated() from e

    return {"token": jwt_token}
