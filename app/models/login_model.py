"""Login request data class module."""

from pydantic import BaseModel


class LoginRequest(BaseModel):
    """Data class with the credentials of a user logging in."""

    username: str
    password: str
