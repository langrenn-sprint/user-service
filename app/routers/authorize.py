"""Resource module for authorize resources."""

import logging
import traceback
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

logger = logging.getLogger("app.authorize_view.AuthorizeView")


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
        logger.debug(traceback.format_exc())
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED, detail=str(e)) from e
    except (UserNotAuthorizedError, InconsistentTokenError) as e:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail=str(e)) from e

    return Response(status_code=204)
