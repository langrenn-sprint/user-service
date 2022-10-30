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
        except json.decoder.JSONDecodeError as e:
            raise web.HTTPBadRequest(reason="Invalid data in request body.") from e

        username = body.get("username", None)
        password = body.get("password", None)
        try:
            jwt_token = await LoginService.login(db, username, password)
        except (UnknownUserException, WrongPasswordException) as e:
            raise web.HTTPUnauthorized(reason="Incorrect username or password") from e

        return web.json_response({"token": jwt_token})
