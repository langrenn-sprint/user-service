"""Resource module for activation: a user sets the password with a code."""

import logging
from http import HTTPStatus

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.models import ActivationRequest
from app.services import (
    InvalidActivationCodeError,
    PasswordTooShortError,
    UsersService,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/activate",
    status_code=HTTPStatus.NO_CONTENT,
    responses={
        HTTPStatus.BAD_REQUEST: {
            "description": "The code is unknown, used or expired."
        },
        HTTPStatus.UNPROCESSABLE_ENTITY: {"description": "The password is too short."},
    },
)
async def activate(request: ActivationRequest) -> Response:
    """Set the password with an activation code. Open: needs no token.

    The code can only be used once.
    """
    try:
        await UsersService.activate(request.code, request.password.get_secret_value())
    except PasswordTooShortError as e:
        raise HTTPException(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail=str(e)
        ) from e
    except InvalidActivationCodeError as e:
        logger.warning("Activation failed: %s", e)
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(e)) from e
    return Response(status_code=HTTPStatus.NO_CONTENT)
