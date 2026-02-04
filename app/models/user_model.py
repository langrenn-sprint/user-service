"""User data class module."""

from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class Role(StrEnum):
    """Enum representing different valid roles."""

    ADMIN = "admin"
    USER_ADMIN = "user-admin"
    EVENT_ADMIN = "event-admin"


class User(BaseModel):
    """Data class with details about a user."""

    model_config = ConfigDict(
        populate_by_name=True,
    )

    id: UUID = Field(default_factory=uuid4)
    username: str
    role: Role
    password: SecretStr
