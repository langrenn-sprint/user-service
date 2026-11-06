"""Resource module for users resources."""

import logging
import os
from http import HTTPStatus
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, Response

from app.adapters import UsersAdapter
from app.authorization import TokenData, get_current_token, require_roles
from app.models import Activation, Role, User, UserInfo
from app.services import (
    CannotDeleteSelfError,
    IllegalValueError,
    PasswordTooShortError,
    UserNotFoundError,
    UsersService,
    user_info,
)

HOST_SERVER = os.getenv("HOST_SERVER", "localhost")
HOST_PORT = os.getenv("HOST_PORT", "8000")
BASE_URL = f"http://{HOST_SERVER}:{HOST_PORT}"

router = APIRouter()

logger = logging.getLogger(__name__)


@router.get("/users", dependencies=[require_roles(Role.ADMIN)])
async def get_users() -> list[UserInfo]:
    """Get route function."""
    return [user_info(document) for document in await UsersAdapter.get_all_users()]


@router.post(
    "/users",
    dependencies=[require_roles(Role.ADMIN)],
    status_code=HTTPStatus.CREATED,
    responses={
        HTTPStatus.CREATED: {
            "model": Activation,
            "description": (
                "Created. Without password in the request, the body has the "
                "activation code; this is the only time it can be read."
            ),
        }
    },
)
async def post(user: User) -> Response:
    """Create a user, with a password or with an activation code."""
    try:
        user_id, activation = await UsersService.create_user(user)
    except IllegalValueError as e:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(e)) from e
    except PasswordTooShortError as e:
        raise HTTPException(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail=str(e)
        ) from e
    if user_id:
        logger.debug("inserted document with id %s", user_id)
        headers = {"Location": f"/users/{user_id}"}
        if activation:
            return JSONResponse(
                status_code=HTTPStatus.CREATED,
                headers=headers,
                content=jsonable_encoder(activation),
            )
        return Response(status_code=HTTPStatus.CREATED, headers=headers)
    raise HTTPException(status_code=HTTPStatus.BAD_REQUEST) from None


@router.get(
    "/users/{user_id}",
    dependencies=[require_roles(Role.ADMIN)],
)
async def get_user_by_id(user_id: UUID) -> UserInfo:
    """Get route function."""
    logger.debug("Got get request for user %s", user_id)
    document = await UsersAdapter.get_user_document(user_id)
    if not document:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND) from None

    return user_info(document)


@router.put(
    "/users/{user_id}",
    dependencies=[require_roles(Role.ADMIN)],
)
async def put(user_id: UUID, user: User) -> Response:
    """Put route function."""
    logger.debug("Got request-body %s for %s of type %s", user, user_id, type(user))
    try:
        await UsersService.update_user(user_id, user)
    except IllegalValueError as e:
        raise HTTPException(status_code=HTTPStatus.UNPROCESSABLE_ENTITY) from e
    except PasswordTooShortError as e:
        raise HTTPException(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY, detail=str(e)
        ) from e
    except UserNotFoundError as e:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND) from e
    return Response(status_code=HTTPStatus.NO_CONTENT)


@router.post(
    "/users/{user_id}/activation",
    dependencies=[require_roles(Role.ADMIN)],
    status_code=HTTPStatus.CREATED,
)
async def create_activation(user_id: UUID) -> Activation:
    """Give the user a new activation code, e.g. to reset the password.

    Earlier codes stop working. A password the user has keeps working until
    the user sets a new one with the code. This is the only time the code can
    be read.
    """
    try:
        return await UsersService.create_activation(user_id)
    except UserNotFoundError as e:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND) from e


@router.delete(
    "/users/{user_id}",
    dependencies=[require_roles(Role.ADMIN)],
)
async def delete(
    user_id: UUID, token: Annotated[TokenData, Depends(get_current_token)]
) -> Response:
    """Delete a user. A user cannot delete the user they are logged in as."""
    # Process request:
    logger.debug("Got delete request for user %s", user_id)

    try:
        await UsersService.delete_user(user_id, token.sub)
    except UserNotFoundError as e:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND) from e
    except CannotDeleteSelfError as e:
        raise HTTPException(status_code=HTTPStatus.CONFLICT, detail=str(e)) from e
    return Response(status_code=HTTPStatus.NO_CONTENT)
