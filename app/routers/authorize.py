"""Resource module for authorize resources."""

import logging
from http import HTTPStatus

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.models import AuthorizationRequest
from app.services import (
    AuthorizationService,
    IncompleteTokenError,
    InconsistentTokenError,
    InvalidTokenError,
    UserNotAuthorizedError,
)

router = APIRouter()

logger = logging.getLogger(__name__)


@router.post("/authorize")
async def post(authorization_request: AuthorizationRequest) -> Response:
    """Authorize route function."""
    # Process:
    try:
        await AuthorizationService.authorize(
            autorization_request=authorization_request,
        )
    except (
        InvalidTokenError,
        IncompleteTokenError,
    ) as e:
        # A routine client error: log one line, without a stack trace.
        logger.warning("Authorization failed: %s", e)
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail=str(e)) from e
    except (UserNotAuthorizedError, InconsistentTokenError) as e:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail=str(e)) from e

    return Response(status_code=204)
