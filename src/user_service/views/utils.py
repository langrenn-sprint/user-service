"""Resource module for utils."""
from typing import Optional

from aiohttp.web import (
    Request,
)


async def extract_token_from_request(request: Request) -> Optional[str]:
    """Extract jwt_token from authorization header in request."""
    jwt_token = None
    authorization = request.headers.get("authorization", None)
    if authorization:
        jwt_token = str.replace(str(authorization), "Bearer ", "")

    return jwt_token
