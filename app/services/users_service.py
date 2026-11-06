"""Module for users service."""

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import SecretStr

from app.adapters import UsersAdapter
from app.models import Activation, User, UserInfo

from .activation import hash_activation_code, new_activation_code
from .passwords import (
    MIN_PASSWORD_LENGTH,
    PASSWORD_HASH_MONGO_REGEX,
    hash_password,
    is_password_hash,
)

logger = logging.getLogger(__name__)


class IllegalValueError(Exception):
    """Class representing custom exception for fetch method."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class UserNotFoundError(Exception):
    """Class representing custom exception for fetch method."""

    def __init__(self, message: str) -> None:
        """Initialize the error."""
        # Call the base class constructor with the parameters it needs
        super().__init__(message)


class PasswordTooShortError(Exception):
    """The password is shorter than MIN_PASSWORD_LENGTH."""

    def __init__(self) -> None:
        """Initialize the error."""
        super().__init__(
            f"Password must have at least {MIN_PASSWORD_LENGTH} characters."
        )


class CannotDeleteSelfError(Exception):
    """A user tried to delete the user they are logged in as."""

    def __init__(self) -> None:
        """Initialize the error."""
        super().__init__("You cannot delete the user you are logged in as.")


class InvalidActivationCodeError(Exception):
    """The activation code is unknown, used or expired.

    The same error for all three, so that the response does not reveal which
    codes exist.
    """

    def __init__(self) -> None:
        """Initialize the error."""
        super().__init__("The activation code is invalid or has expired.")


def _password(user: User) -> str | None:
    """Return the user's password, or None if it is missing or empty."""
    if user.password is None:
        return None
    return user.password.get_secret_value() or None


def _check_length(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordTooShortError


def user_info(document: dict) -> UserInfo:
    """Return what is shown about a stored user."""
    expires = document.get("activation_expires")
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)  # MongoDB stores UTC, naive
    return UserInfo(
        id=document["id"],
        username=document["username"],
        role=document["role"],
        activated=bool(document.get("password")),
        activation_expires=expires,
    )


class UsersService:
    """Class representing a service for users."""

    @classmethod
    async def create_user(
        cls: Any, user: User
    ) -> tuple[UUID | None, Activation | None]:
        """Create user function.

        A user created without password gets an activation code, so that the
        user can set the password.

        Args:
            user (User): a user instanse to be created

        Returns:
            The id of the created user, None otherwise; and the activation
            code for a user without password.

        Raises:
            IllegalValueError: input object has illegal values
            PasswordTooShortError: the password is too short

        """
        # Validation:
        if user.username == "admin":
            msg = 'Cannot create user with username "admin".'
            raise IllegalValueError(msg) from None
        password = _password(user)
        activation = None
        stored_activation = None
        if password is None:
            user.password = None
            code, code_hash, expires = new_activation_code()
            activation = Activation(user_id=user.id, code=code, expires=expires)
            stored_activation = {
                "activation_code_hash": code_hash,
                "activation_expires": expires,
            }
        else:
            _check_length(password)
            # Store a hash of the password, never the password itself:
            user.password = SecretStr(await hash_password(password))
        # insert new user
        result = await UsersAdapter.create_user(user, stored_activation)
        logger.debug("inserted user with id: %s", user.id)
        if result:
            return user.id, activation
        return None, None

    @classmethod
    async def update_user(cls: Any, user_id: UUID, user: User) -> UUID | None:
        """Get user function."""
        # Validation:
        if user.username == "admin":
            msg = 'Cannot change username to "admin".'
            raise IllegalValueError(msg) from None
        # get old document
        old_user = await UsersAdapter.get_user_by_id(user_id)
        # update the user if found:
        if old_user:
            if user.id != old_user.id:
                msg = "Cannot change id for user."
                raise IllegalValueError(msg) from None
            password = _password(user)
            if password is None:
                user.password = None  # keep the stored password
            else:
                _check_length(password)
                # Store a hash of the password, never the password itself:
                user.password = SecretStr(await hash_password(password))
            return await UsersAdapter.update_user(user_id, user)
        msg = f"User with id {user_id} not found."
        raise UserNotFoundError(msg) from None

    @classmethod
    async def create_activation(cls: Any, user_id: UUID) -> Activation:
        """Give the user a new activation code, e.g. to reset the password.

        Earlier codes stop working. A password the user has keeps working
        until the user sets a new one with the code.

        Raises:
            UserNotFoundError: the user does not exist

        """
        code, code_hash, expires = new_activation_code()
        if not await UsersAdapter.set_activation(user_id, code_hash, expires):
            msg = f"User with id {user_id} not found."
            raise UserNotFoundError(msg) from None
        return Activation(user_id=user_id, code=code, expires=expires)

    @classmethod
    async def activate(
        cls: Any, code: str, password: str, username: str | None = None
    ) -> None:
        """Set the password of the user with the activation code.

        If username is given, it must be the user the code was given to.

        Raises:
            PasswordTooShortError: the password is too short
            InvalidActivationCodeError: the code is unknown, used or expired

        """
        _check_length(password)
        # Hash the password first, so that unknown and known codes take the
        # same time:
        password_hash = await hash_password(password)
        if not await UsersAdapter.activate(
            hash_activation_code(code), datetime.now(UTC), password_hash, username
        ):
            raise InvalidActivationCodeError

    @classmethod
    async def hash_plaintext_passwords(cls: Any) -> int:
        """Replace every password stored in plain text with a hash of it.

        Users stored before passwords were hashed have their password in plain
        text. This runs on startup, and does nothing for passwords that are
        already hashed, so it is safe to run repeatedly.

        Returns:
            int: The number of passwords that were hashed.

        """
        count = 0
        users = await UsersAdapter.get_users_with_plaintext_password(
            PASSWORD_HASH_MONGO_REGEX
        )
        for user in users:
            password = user["password"]
            if is_password_hash(password):  # pragma: no cover
                continue  # the query should not return hashed passwords
            # Only replaces the password if it has not been changed meanwhile:
            if await UsersAdapter.update_password(
                user["id"], password, await hash_password(password)
            ):
                count += 1
        return count

    @classmethod
    async def delete_user(cls: Any, user_id: UUID, current_username: str) -> None:
        """Delete user.

        Raises:
            UserNotFoundError: the user does not exist
            CannotDeleteSelfError: the user is the one logged in

        """
        # get old document
        user = await UsersAdapter.get_user_by_id(user_id)
        if user and user.username == current_username:
            raise CannotDeleteSelfError
        # delete the document if found:
        if user:
            await UsersAdapter.delete_user(user.id)
        else:
            msg = f"User with id {user_id} not found"
            raise UserNotFoundError(msg) from None
