"""Resource module for users resources."""

import logging
import os
from http import HTTPStatus
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from app.adapters import UsersAdapter
from app.authorization import (
    RoleChecker,
)
from app.models import Role, User
from app.services import (
    IllegalValueError,
    UsersService,
)
from app.services.users_service import UserNotFoundError

HOST_SERVER = os.getenv("HOST_SERVER", "localhost")
HOST_PORT = os.getenv("HOST_PORT", "8000")
BASE_URL = f"http://{HOST_SERVER}:{HOST_PORT}"

router = APIRouter()

logger = logging.getLogger("app.users_view.UsersView")


@router.get(
    "/users", dependencies=[Depends(RoleChecker([Role.ADMIN, Role.USER_ADMIN]))]
)
async def get_users() -> list[User]:
    """Get route function."""
    return await UsersAdapter.get_all_users()


@router.post(
    "/users", dependencies=[Depends(RoleChecker([Role.ADMIN, Role.USER_ADMIN]))]
)
async def post(user: User) -> Response:
    """Post route function."""
    try:
        user_id = await UsersService.create_user(user)
    except IllegalValueError as e:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(e)) from e
    if user_id:
        logger.debug("inserted document with id %s", user_id)
        headers = {"Location": f"/users/{user_id}"}

        return Response(status_code=HTTPStatus.CREATED, headers=headers)
    raise HTTPException(status_code=HTTPStatus.BAD_REQUEST) from None


@router.get(
    "/users/{user_id}",
    dependencies=[Depends(RoleChecker([Role.ADMIN, Role.USER_ADMIN]))],
)
async def get_user_by_id(user_id: UUID) -> User:
    """Get route function."""
    logger.debug("Got get request for user %s", user_id)
    user = await UsersAdapter.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND) from None

    return user


@router.put(
    "/users/{user_id}",
    dependencies=[Depends(RoleChecker([Role.ADMIN, Role.USER_ADMIN]))],
)
async def put(user_id: UUID, user: User) -> Response:
    """Put route function."""
    logger.debug("Got request-body %s for %s of type %s", user, user_id, type(user))
    try:
        await UsersService.update_user(user_id, user)
    except IllegalValueError as e:
        raise HTTPException(status_code=HTTPStatus.UNPROCESSABLE_ENTITY) from e
    except UserNotFoundError as e:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND) from e
    return Response(status_code=HTTPStatus.NO_CONTENT)


@router.delete(
    "/users/{user_id}",
    dependencies=[Depends(RoleChecker([Role.ADMIN, Role.USER_ADMIN]))],
)
async def delete(user_id: UUID) -> Response:
    """Delete route function."""
    # Process request:
    logger.debug("Got delete request for user %s", user_id)

    try:
        await UsersService.delete_user(user_id)
    except UserNotFoundError as e:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND) from e
    return Response(status_code=HTTPStatus.NO_CONTENT)
