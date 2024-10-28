"""User data class module."""

from dataclasses import dataclass, field
from enum import Enum

from dataclasses_json import DataClassJsonMixin


class Role(str, Enum):
    """Enum representing different valid roles."""

    ADMIN = "admin"
    USER_ADMIN = "user-admin"
    EVENT_ADMIN = "event-admin"


@dataclass
class User(DataClassJsonMixin):
    """Data class with details about a user."""

    username: str
    role: str
    password: str | None = field(default=None)
    id: str | None = field(default=None)
