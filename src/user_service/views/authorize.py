"""Resource module for authorize resources."""
import json
import logging
import traceback

from aiohttp.web import (
    HTTPBadRequest,
    HTTPForbidden,
    HTTPUnauthorized,
    Response,
    View,
)

from user_service.services import (
    AuthorizationService,
    IncompleteTokenException,
    InconsistentTokenException,
    InvalidInputException,
    InvalidTokenException,
    UserNotAuthorizedException,
)


class AuthorizeView(View):
    """Class representing authorize resource."""

    async def post(self) -> Response:
        """Authorize route function."""
        db = self.request.app["db"]
        try:
            body = await self.request.json()
        except json.decoder.JSONDecodeError as e:
            raise HTTPBadRequest(reason="Invalid data in request body.") from e

        # Process:
        try:
            await AuthorizationService.authorize(
                db, body.get("token", None), body.get("roles", None)
            )
        except (
            InvalidTokenException,
            InvalidInputException,
            IncompleteTokenException,
        ) as e:
            logging.debug(traceback.format_exc())
            raise HTTPUnauthorized(reason=e) from e
        except (UserNotAuthorizedException, InconsistentTokenException) as e:
            raise HTTPForbidden(reason=e) from e

        return Response(status=204)
