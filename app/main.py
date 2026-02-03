"""Module for admin of sporting users."""

import logging
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import motor.motor_asyncio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .adapters import LivenessAdapter, UsersAdapter
from .authorization import (
    TokenError,
    TokenMissingError,
    TokenValidationError,
)
from .routers import authorize, login, ping, ready, users

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "27017"))
DB_NAME = os.getenv("DB_NAME", "users")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")


class EndpointFilter(logging.Filter):
    """Logging filter to exclude specific endpoints from access logs."""

    def __init__(self, excluded_endpoints: list[str]) -> None:
        """Initialize the filter with a list of endpoints to exclude."""
        super().__init__()
        self.excluded_endpoints = excluded_endpoints

    def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover
        """Filter log records to exclude specified endpoints."""
        # Assuming the endpoint path is available in record.args[2]
        # for Uvicorn access logs
        if (  # noqa: SIM103
            record.args
            and len(record.args) >= 3  # noqa: PLR2004
            and record.args[2] in self.excluded_endpoints  # type: ignore[invalid-argument-type]
        ):
            return False  # Exclude this log record
        return True  # Include this log record


logger = logging.getLogger("uvicorn.error")
access_logger = logging.getLogger("uvicorn.access")
logging.getLogger("alembic").setLevel(logging.WARNING)
# Exclude metrics and health check endpoint from access logs
excluded_endpoints = ["/health", "/metrics"]
access_logger.addFilter(EndpointFilter(excluded_endpoints))


@asynccontextmanager
async def lifespan(api: FastAPI) -> AsyncGenerator[None]:  # noqa: ARG001  # pragma: no cover
    """Start adapters and internal message consumer on app startup."""
    # Initialize database:
    msg = f"Connecting to db at {DB_HOST}:{DB_PORT}"
    logger.debug(msg)
    mongo = motor.motor_asyncio.AsyncIOMotorClient(
        host=DB_HOST,
        port=DB_PORT,
        username=DB_USER,
        password=DB_PASSWORD,
        uuidRepresentation="standard",
    )
    db = mongo[f"{DB_NAME}"]

    await LivenessAdapter.init(db)
    await UsersAdapter.init(db)

    yield

    # Cleanup resources if needed
    mongo.close()


api = FastAPI(
    lifespan=lifespan,
    title="User Service",
    version="1.0.0",
    separate_input_output_schemas=False,
)


@api.exception_handler(TokenError)
async def unicorn_exception_handler(
    request: Request, exc: TokenError
) -> JSONResponse:  # pragma: no cover
    """Handle token validation errors."""
    _ = request  # Unused variable
    _ = exc  # Unused variable
    if isinstance(exc, TokenMissingError):
        return JSONResponse(
            status_code=401,
            content={"detail": "Not authenticated"},
        )
    if isinstance(exc, TokenValidationError):
        return JSONResponse(
            status_code=403,
            content={"detail": "Not authorized to access this resource"},
        )
    return JSONResponse(
        status_code=403,
        content={"detail": "Not authorized to access this resource"},
    )


# Set up routes:
api.include_router(ping.router)
api.include_router(ready.router)
api.include_router(login.router)
api.include_router(users.router)
api.include_router(authorize.router)
