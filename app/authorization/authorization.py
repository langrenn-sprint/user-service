"""Authorization dependencies for FastAPI routes."""

import logging
import os
from dataclasses import dataclass
from http import HTTPStatus
from typing import Annotated, Any

import jwt
from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)

from app.models import Role

# Set upp logging:
logger = logging.getLogger(__name__)


class TokenError(Exception):
    """Base class for token-related errors."""


class TokenMissingError(TokenError):
    """Custom exception for missing token errors."""


class TokenValidationError(TokenError):
    """Custom exception for token validation errors."""


class APIConfigurationError(TokenError):
    """Custom exception for API configuration errors."""


class APIKeyError(TokenError):
    """Custom exception for API key errors."""


# Token validation
class TokenValidator:
    """Class to validate JWT tokens."""

    def validate_token(self, token: str) -> dict[str, Any]:  # pragma: no cover
        """Validate JWT token from either flow."""
        try:
            secret_key = os.getenv("JWT_SECRET")
            if not secret_key:
                msg = "JWT secret key is not configured"
                logger.error(msg)
                raise APIConfigurationError(msg)
            # Validate token
            return jwt.decode(
                token,
                secret_key,
                algorithms=["HS256"],
            )

        except jwt.ExpiredSignatureError as e:
            msg = "Token has expired"
            logger.warning(msg)
            raise TokenValidationError(msg) from e
        except jwt.InvalidSignatureError as e:
            msg = "Token signature is invalid"
            logger.warning(msg)
            raise TokenValidationError(msg) from e
        except jwt.DecodeError as e:
            msg = "Token could not be decoded"
            logger.warning(msg)
            raise TokenValidationError(msg) from e
        except jwt.MissingRequiredClaimError as e:
            msg = f"Token is missing required claim: {e!s}"
            logger.warning(msg)
            raise TokenValidationError(msg) from e
        except jwt.InvalidTokenError as e:
            msg = "Token is invalid"
            logger.warning(msg)
            raise TokenValidationError(msg) from e


# Token models
@dataclass
class TokenData:
    """Data class for token data."""

    sub: str
    name: str
    roles: list[str]
    exp: int


bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_token(
    http_credentials: Annotated[
        HTTPAuthorizationCredentials | None, Security(bearer_scheme)
    ],
) -> TokenData:  # pragma: no cover
    """Extract and validate token from HTTPBearer."""
    # Determine which token to use
    token = None
    if http_credentials and http_credentials.scheme.lower() == "bearer":
        token = http_credentials.credentials

    if not token:
        msg = "Authorization header missing or not a Bearer token"
        logger.warning(msg)
        raise TokenMissingError(msg)

    # Otherwise, validate as JWT token:
    validator = TokenValidator()
    payload = validator.validate_token(token)

    # Determine token type based on claims
    try:
        # Handle both machine-to-machine and user tokens
        sub = payload["username"]
        name = payload.get("name", "")
        role = payload["role"]
        exp = payload["exp"]
    except KeyError as e:
        msg = f"Missing expected claim in token: {e}"
        logger.warning(msg)
        raise TokenValidationError(msg) from e

    # The claims must also have usable values, e.g. not null or empty:
    for claim, value in (("username", sub), ("role", role)):
        if not isinstance(value, str) or not value:
            msg = f"Invalid {claim} claim in token"
            logger.warning(msg)
            raise TokenValidationError(msg)

    return TokenData(
        sub=sub,
        name=name,
        roles=[role],
        exp=exp,
    )


class RoleChecker:
    """Role checker dependency."""

    def __init__(self, allowed_roles: list[Role]) -> None:
        """Initialize RoleChecker with allowed roles."""
        self.allowed_roles = allowed_roles

    async def __call__(
        self,
        token_data: Annotated[TokenData, Depends(get_current_token)],
    ) -> None:
        """Check if user has one of the allowed roles."""
        # Convert token roles (strings) to UserRole enum for comparison
        user_roles = token_data.roles

        # Check if any of the user's roles match the allowed roles
        for role in user_roles:
            if role in [allowed_role.value for allowed_role in self.allowed_roles]:
                return

        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN, detail="Operation forbidden"
        )


def require_roles(*roles: Role) -> Any:
    """Dependency that allows only users with one of the given roles.

    The roles are also given as scopes on the security requirement, so the
    OpenAPI document lists them for the bearer scheme (allowed for non-OAuth2
    schemes in OpenAPI 3.1). See document_roles for the description text.
    """
    return Security(RoleChecker(list(roles)), scopes=[role.value for role in roles])


def document_roles(api: FastAPI) -> None:
    """Show the allowed roles for each operation in the OpenAPI document.

    For every operation protected by require_roles, the roles are added to
    the description, and the 401 and 403 responses are documented.
    """
    generate_openapi = api.openapi

    def openapi() -> dict[str, Any]:
        if api.openapi_schema:
            return api.openapi_schema
        schema = generate_openapi()
        for path_item in schema.get("paths", {}).values():
            for operation in path_item.values():
                roles = list(
                    dict.fromkeys(
                        role
                        for requirement in operation.get("security", [])
                        for scope in requirement.values()
                        for role in scope
                    )
                )
                if not roles:
                    continue
                roles_text = "**Roles:** " + ", ".join(f"`{r}`" for r in roles)
                description = operation.get("description")
                operation["description"] = (
                    f"{description}\n\n{roles_text}" if description else roles_text
                )
                responses = operation.setdefault("responses", {})
                responses.setdefault("401", {"description": "Missing or invalid token"})
                responses.setdefault(
                    "403",
                    {
                        "description": "Operation forbidden: requires one of the roles "
                        + ", ".join(roles)
                    },
                )
        return schema

    api.openapi = openapi  # ty: ignore[invalid-assignment]
