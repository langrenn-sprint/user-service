"""Resource module for login resources."""

import logging

from fastapi import APIRouter, HTTPException

from app.services import (
    LoginService,
    UnknownUserError,
    WrongPasswordError,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/login")
async def post(user: dict) -> dict:
    """Login route function."""
    try:
        jwt_token = await LoginService.login(user["username"], user["password"])
    except (UnknownUserError, WrongPasswordError) as e:
        raise HTTPException(
            status_code=401, detail="Incorrect username or password"
        ) from e

    return {"token": jwt_token}
