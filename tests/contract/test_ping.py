"""Contract test cases for ping."""

from http import HTTPStatus
from typing import Any

import pytest
from httpx import AsyncClient


@pytest.mark.contract
@pytest.mark.asyncio
async def test_ping(http_service: Any) -> None:
    """Should return OK."""
    url = f"{http_service}/ping"

    async with AsyncClient() as client:
        response = await client.get(url)
        text = response.text

    assert response.status_code == HTTPStatus.OK
    assert text == "OK"
