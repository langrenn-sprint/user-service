"""Module for users adapter."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


class LivenessAdapter:
    """Class representing an adapter for the liveness connection."""

    database: Any

    @classmethod
    async def init(cls, database: Any) -> None:  # pragma: no cover
        """Initialize class properties."""
        cls.database = database

    @classmethod
    async def database_is_ready(cls) -> bool:  # pragma: no cover
        """Check if the database connection is ready."""
        try:
            result = await cls.database.command("ping")
        except Exception:
            logger.exception("Error pinging database")
            return False
        msg = f"result of db-ping: {result}"
        logger.debug(msg)
        return result["ok"] == 1
