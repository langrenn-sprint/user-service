"""Resource module for authorize resources."""
import json

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
        except json.decoder.JSONDecodeError:
            raise HTTPBadRequest(reason="Invalid data in request body.")

        # Process:
        try:
            await AuthorizationService.authorize(
                db, body.get("token", None), body.get("roles", None)
            )
        except (
            InvalidInputException,
            InconsistentTokenException,
            IncompleteTokenException,
        ) as e:
            raise HTTPBadRequest(reason=e)
        except InvalidTokenException:
            raise HTTPUnauthorized()
        except UserNotAuthorizedException:
            raise HTTPForbidden()

        return Response(status=204)
