"""Resource module for login resources."""
import json

from aiohttp import web

from user_service.services import (
    LoginService,
    UnknownUserException,
    WrongPasswordException,
)


class LoginView(web.View):
    """Class representing login resource."""

    async def post(self) -> web.Response:
        """Login route function."""
        db = self.request.app["db"]
        try:
            body = await self.request.json()
        except json.decoder.JSONDecodeError:
            raise web.HTTPBadRequest(reason="Invalid data in request body.")

        username = body.get("username", None)
        password = body.get("password", None)
        try:
            jwt_token = await LoginService.login(db, username, password)
        except UnknownUserException:
            raise web.HTTPUnauthorized(reason=f"Unknown user {username}.")
        except WrongPasswordException:
            raise web.HTTPUnauthorized(reason=f"Wrong password for user {username}.")

        return web.json_response({"token": jwt_token})
