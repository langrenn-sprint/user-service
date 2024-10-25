"""Conftest module."""

import time
from http import HTTPStatus
from os import environ as env
from pathlib import Path
from typing import Any

import pytest
import requests
from aiohttp.test_utils import TestClient as _TestClient
from dotenv import load_dotenv
from requests.exceptions import ConnectionError

from user_service import create_app

load_dotenv()
HOST_PORT = int(env.get("HOST_PORT", "8080"))


@pytest.fixture
async def client(aiohttp_client: Any) -> _TestClient:
    """Instantiate server and start it."""
    app = await create_app()
    return await aiohttp_client(app)


def is_responsive(url: str) -> bool:
    """Return true if response from service is 200."""
    url = f"{url}/ready"
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == HTTPStatus.OK:
            time.sleep(2)  # sleep extra 2 sec
            return True
    except ConnectionError:
        pass
    return False


@pytest.fixture(scope="session")
def http_service(docker_ip: Any, docker_services: Any) -> Any:
    """Ensure that HTTP service is up and responsive."""
    # `port_for` takes a container port and returns the corresponding host port
    port = docker_services.port_for("user-service", HOST_PORT)
    url = f"http://{docker_ip}:{port}"
    docker_services.wait_until_responsive(
        timeout=30.0, pause=0.1, check=lambda: is_responsive(url)
    )
    return url


@pytest.fixture(scope="session")
def docker_compose_file(pytestconfig: Any) -> Any:
    """Override default location of docker-compose.yml file."""
    return Path(str(pytestconfig.rootdir)) / "docker-compose.yml"
