"""Module for admin of sporting users."""

import logging
import os
from collections.abc import AsyncGenerator
from typing import Any

from aiohttp import web
from aiohttp.web_app import Application
from aiohttp_middlewares.cors import cors_middleware
from aiohttp_middlewares.error import error_middleware
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from .views import (
    AuthorizeView,
    LoginView,
    PingView,
    ReadyView,
    UsersView,
    UserView,
)

LOGGING_LEVEL = os.getenv("LOGGING_LEVEL", "INFO")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "27017"))
DB_NAME = os.getenv("DB_NAME", "users")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")


async def create_app() -> web.Application:
    """Create an web application."""
    app = web.Application(
        middlewares=[
            cors_middleware(allow_all=True),
            error_middleware(),  # default error handler for whole application
        ]
    )
    # Set up logging
    logging.basicConfig(level=LOGGING_LEVEL)
    logging.getLogger("chardet.charsetprober").setLevel(LOGGING_LEVEL)

    # Set up routes:
    app.add_routes(
        [
            web.view("/login", LoginView),
            web.view("/authorize", AuthorizeView),
            web.view("/ping", PingView),
            web.view("/ready", ReadyView),
            web.view("/users", UsersView),
            web.view("/users/{id}", UserView),
        ]
    )

    async def mongo_context(app: Application) -> AsyncGenerator[None, None]:
        # Set up database connection:
        logging.debug("Connecting to db at %s:%s", DB_HOST, DB_PORT)
        client: AsyncIOMotorClient[dict[str, Any]] = AsyncIOMotorClient(
            host=DB_HOST, port=DB_PORT, username=DB_USER, password=DB_PASSWORD
        )
        db: AsyncIOMotorDatabase = client[f"{DB_NAME}"]
        app["db"] = db

        yield

        client.close()

    app.cleanup_ctx.append(mongo_context)

    return app
