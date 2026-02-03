"""Route module for ready resources."""

import logging
import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from app.adapters import LivenessAdapter

CONFIG = os.getenv("CONFIG", "production")

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/ready",
    response_class=PlainTextResponse,
)
async def ready() -> str:
    """Ready route function."""
    if CONFIG in {"test", "dev"}:
        pass
    elif CONFIG == "production":  # pragma: no cover
        if await LivenessAdapter.database_is_ready():
            pass
        else:
            raise HTTPException(status_code=500, detail="Database not ready")

    return "OK"
