"""Resource module for login resources."""

import logging

from fastapi import APIRouter, HTTPException

from app.models import LoginRequest
from app.services import (
    LoginService,
    UnknownUserError,
    UserNotActivatedError,
    WrongPasswordError,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/login")
async def post(login_request: LoginRequest) -> dict:
    """Login route function."""
    try:
        jwt_token = await LoginService.login(
            login_request.username, login_request.password
        )
    except (UnknownUserError, WrongPasswordError) as e:
        raise HTTPException(
            status_code=401, detail="Incorrect username or password"
        ) from e
    except UserNotActivatedError as e:
        raise HTTPException(
            status_code=403,
            detail="User is not activated. Use the activation link.",
        ) from e

    return {"token": jwt_token}
