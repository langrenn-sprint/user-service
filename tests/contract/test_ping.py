"""Contract test cases for ping."""

from http import HTTPStatus
from typing import Any

import pytest
from aiohttp import ClientSession


@pytest.mark.contract
@pytest.mark.asyncio
async def test_ping(http_service: Any) -> None:
    """Should return OK."""
    url = f"{http_service}/ping"

    session = ClientSession()
    async with session.get(url) as response:
        text = await response.text()
    await session.close()

    assert response.status == HTTPStatus.OK
    assert text == "OK"
