"""User data class module."""

from pydantic import BaseModel, ConfigDict


class AuthorizationRequest(BaseModel):
    """Data class with details about a user."""

    model_config = ConfigDict(
        populate_by_name=True,
    )
    token: str
    target_roles: list[str]
