"""Resource module for users resources."""
import json
import logging
import os

from aiohttp import hdrs
from aiohttp.web import (
    HTTPBadRequest,
    HTTPNotFound,
    HTTPUnprocessableEntity,
    Response,
    View,
)
from dotenv import load_dotenv
from multidict import MultiDict

from user_service.models import Role, User
from user_service.services import (
    AuthorizationService,
    IllegalValueException,
    UserNotFoundException,
    UsersService,
)
from .utils import extract_token_from_request

load_dotenv()
HOST_SERVER = os.getenv("HOST_SERVER", "localhost")
HOST_PORT = os.getenv("HOST_PORT", "8080")
BASE_URL = f"http://{HOST_SERVER}:{HOST_PORT}"


class UsersView(View):
    """Class representing users resource."""

    async def get(self) -> Response:
        """Get route function."""
        db = self.request.app["db"]
        # Authenticate and authorize:
        token = await extract_token_from_request(self.request)
        await AuthorizationService.authorize(db, token, [Role.ADMIN, Role.USER_ADMIN])

        # Process request:
        users = await UsersService.get_all_users(db)
        body = json.dumps(users, default=str, ensure_ascii=False)
        return Response(status=200, body=body, content_type="application/json")

    async def post(self) -> Response:
        """Post route function."""
        db = self.request.app["db"]
        # Authenticate and authorize:
        token = await extract_token_from_request(self.request)
        await AuthorizationService.authorize(db, token, [Role.ADMIN, Role.USER_ADMIN])

        # Process request:
        body = await self.request.json()
        logging.debug(f"Got create request for user {body} of type {type(body)}")

        try:
            user = User.from_dict(body)
        except KeyError as e:
            raise HTTPUnprocessableEntity(
                reason=f"Mandatory property {e.args[0]} is missing."
            ) from e

        try:
            id = await UsersService.create_user(db, user)
        except IllegalValueException as e:
            raise HTTPUnprocessableEntity() from e
        if id:
            logging.debug(f"inserted document with id {id}")
            headers = MultiDict([(hdrs.LOCATION, f"{BASE_URL}/users/{id}")])

            return Response(status=201, headers=headers)
        raise HTTPBadRequest() from None


class UserView(View):
    """Class representing a single user resource."""

    async def get(self) -> Response:
        """Get route function."""
        db = self.request.app["db"]
        # Authenticate and authorize:
        token = await extract_token_from_request(self.request)
        await AuthorizationService.authorize(db, token, [Role.ADMIN, Role.USER_ADMIN])

        # Process request:
        id = self.request.match_info["id"]
        logging.debug(f"Got get request for user {id}")
        try:
            user = await UsersService.get_user_by_id(db, id)
        except UserNotFoundException as e:
            raise HTTPNotFound() from e

        logging.debug(f"Got user: {user}")
        body = user.to_json()
        return Response(status=200, body=body, content_type="application/json")

    async def put(self) -> Response:
        """Put route function."""
        db = self.request.app["db"]
        # Authenticate and authorize:
        token = await extract_token_from_request(self.request)
        await AuthorizationService.authorize(db, token, [Role.ADMIN, Role.USER_ADMIN])

        # Process request:
        body = await self.request.json()
        try:
            user = User.from_dict(body)
        except KeyError as e:
            raise HTTPUnprocessableEntity(
                reason=f"Mandatory property {e.args[0]} is missing."
            ) from e

        id = self.request.match_info["id"]
        logging.debug(f"Got request-body {body} for {id} of type {type(body)}")
        try:
            await UsersService.update_user(db, id, user)
        except IllegalValueException as e:
            raise HTTPUnprocessableEntity() from e
        except UserNotFoundException as e:
            raise HTTPNotFound() from e
        return Response(status=204)

    async def delete(self) -> Response:
        """Delete route function."""
        db = self.request.app["db"]
        # Authenticate and authorize:
        token = await extract_token_from_request(self.request)
        await AuthorizationService.authorize(db, token, [Role.ADMIN, Role.USER_ADMIN])

        # Process request:
        id = self.request.match_info["id"]
        logging.debug(f"Got delete request for user {id}")

        try:
            await UsersService.delete_user(db, id)
        except UserNotFoundException as e:
            raise HTTPNotFound() from e
        return Response(status=204)
