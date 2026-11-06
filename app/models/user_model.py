"""User data class module."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class Role(StrEnum):
    """Enum representing different valid roles."""

    ADMIN = "admin"
    EVENT_ADMIN = "event-admin"
    RESULT_ADMIN = "result-admin"
    CONTESTANT_ADMIN = "contestant-admin"


class User(BaseModel):
    """Data class with details about a user.

    A user without password is not activated: the user sets the password with
    an activation code, see Activation.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )

    id: UUID = Field(default_factory=uuid4)
    username: str
    role: Role
    password: SecretStr | None = None


class UserInfo(BaseModel):
    """What is shown about a user: never the password or the activation code."""

    id: UUID
    username: str
    role: Role
    activated: bool = Field(description="True if the user has a password.")
    activation_expires: datetime | None = Field(
        default=None,
        description="When the user's activation code expires, if there is one.",
    )


class Activation(BaseModel):
    """A new activation code for a user. This is the only time it can be read."""

    user_id: UUID
    code: str
    expires: datetime


class ActivationRequest(BaseModel):
    """A user setting the password with an activation code."""

    code: str
    password: SecretStr
    username: str | None = Field(
        default=None,
        description=(
            "The username the code was given to, if known. If given, it must "
            "match, so the browser saves the password for the right user."
        ),
    )
