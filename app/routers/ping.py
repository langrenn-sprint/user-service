"""Route module for ping resources."""

import logging

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get(
    "/ping",
    response_class=PlainTextResponse,
)
async def ping() -> str:
    """Ping route function."""
    return "OK"
