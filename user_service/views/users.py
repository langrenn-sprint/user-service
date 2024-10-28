"""Resource module for users resources."""

import json
import logging
import os
from http import HTTPStatus

from aiohttp import hdrs
from aiohttp.web import (
    HTTPBadRequest,
    HTTPNotFound,
    HTTPUnprocessableEntity,
    Response,
    View,
)
from aiohttp.web_exceptions import HTTPForbidden
from dotenv import load_dotenv
from multidict import MultiDict

from user_service.models import Role, User
from user_service.services import (
    AuthorizationError,
    AuthorizationService,
    IllegalValueError,
    UsersService,
)
from user_service.services.users_service import UserNotFoundError

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
        try:
            token = await extract_token_from_request(self.request)
            await AuthorizationService.authorize(
                db, token, [Role.ADMIN, Role.USER_ADMIN]
            )
        except AuthorizationError as e:
            raise HTTPForbidden(reason=str(e)) from e

        # Process request:
        users = await UsersService.get_all_users(db)
        # We add to list and remove the password attribute from the response:
        result = []
        for user in users:
            dict_user = user.to_dict()
            dict_user.pop("password", None)
            result.append(dict_user)

        body = json.dumps(result, default=str, ensure_ascii=False)
        return Response(
            status=HTTPStatus.OK, body=body, content_type="application/json"
        )

    async def post(self) -> Response:
        """Post route function."""
        db = self.request.app["db"]
        # Authenticate and authorize:
        try:
            token = await extract_token_from_request(self.request)
            await AuthorizationService.authorize(
                db, token, [Role.ADMIN, Role.USER_ADMIN]
            )
        except AuthorizationError as e:
            logging.exception("Authorization error")
            raise HTTPForbidden(reason=str(e)) from e

        # Process request:
        body = await self.request.json()
        logging.debug("Got create request for user %s of type %s", body, type(body))

        try:
            user = User.from_dict(body)
        except KeyError as e:
            raise HTTPUnprocessableEntity(
                reason=f"Mandatory property {e.args[0]} is missing."
            ) from e

        try:
            user_id = await UsersService.create_user(db, user)
        except IllegalValueError as e:
            raise HTTPUnprocessableEntity from e
        if user_id:
            logging.debug("inserted document with id %s", user_id)
            headers = MultiDict([(hdrs.LOCATION, f"{BASE_URL}/users/{user_id}")])

            return Response(status=HTTPStatus.CREATED, headers=headers)
        raise HTTPBadRequest from None


class UserView(View):
    """Class representing a single user resource."""

    async def get(self) -> Response:
        """Get route function."""
        db = self.request.app["db"]
        # Authenticate and authorize:
        try:
            token = await extract_token_from_request(self.request)
            await AuthorizationService.authorize(
                db, token, [Role.ADMIN, Role.USER_ADMIN]
            )
        except AuthorizationError as e:
            raise HTTPForbidden(reason=str(e)) from e

        # Process request:
        user_id = self.request.match_info["id"]
        logging.debug("Got get request for user %s", user_id)
        try:
            user = await UsersService.get_user_by_id(db, user_id)
        except IllegalValueError as e:
            raise HTTPNotFound from e

        logging.debug("Got user: %s", user)
        # We remove the password attribute from the response:
        user_dict = user.to_dict()
        user_dict.pop("password", None)
        body = json.dumps(user_dict, default=str, ensure_ascii=False)
        return Response(
            status=HTTPStatus.OK, body=body, content_type="application/json"
        )

    async def put(self) -> Response:
        """Put route function."""
        db = self.request.app["db"]
        # Authenticate and authorize:
        try:
            token = await extract_token_from_request(self.request)
            await AuthorizationService.authorize(
                db, token, [Role.ADMIN, Role.USER_ADMIN]
            )
        except AuthorizationError as e:
            raise HTTPForbidden(reason=str(e)) from e

        # Process request:
        body = await self.request.json()
        try:
            user = User.from_dict(body)
        except KeyError as e:
            raise HTTPUnprocessableEntity(
                reason=f"Mandatory property {e.args[0]} is missing."
            ) from e

        user_id = self.request.match_info["id"]
        logging.debug("Got request-body %s for %s of type %s", body, id, type(body))
        try:
            await UsersService.update_user(db, user_id, user)
        except IllegalValueError as e:
            raise HTTPUnprocessableEntity from e
        except UserNotFoundError as e:
            raise HTTPNotFound from e
        return Response(status=HTTPStatus.NO_CONTENT)

    async def delete(self) -> Response:
        """Delete route function."""
        db = self.request.app["db"]
        # Authenticate and authorize:
        try:
            token = await extract_token_from_request(self.request)
            await AuthorizationService.authorize(
                db, token, [Role.ADMIN, Role.USER_ADMIN]
            )
        except AuthorizationError as e:
            raise HTTPForbidden(reason=str(e)) from e

        # Process request:
        user_id = self.request.match_info["id"]
        logging.debug("Got delete request for user %s", user_id)

        try:
            await UsersService.delete_user(db, user_id)
        except UserNotFoundError as e:
            raise HTTPNotFound from e
        return Response(status=HTTPStatus.NO_CONTENT)
