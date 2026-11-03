"""Unit test cases for the logging configuration."""

import logging
from collections.abc import Iterator

import pytest

from app.main import configure_logging


@pytest.fixture
def restore_app_logger_level() -> Iterator[None]:
    """Restore the level of the app logger after the test."""
    app_logger = logging.getLogger("app")
    level = app_logger.level
    yield
    app_logger.setLevel(level)


@pytest.mark.unit
@pytest.mark.usefixtures("restore_app_logger_level")
def test_configure_logging_sets_level() -> None:
    """Should set the level of the app logger, case insensitively."""
    configure_logging("debug")
    assert logging.getLogger("app").level == logging.DEBUG


@pytest.mark.unit
@pytest.mark.usefixtures("restore_app_logger_level")
def test_configure_logging_empty_level_defaults_to_info() -> None:
    """Should use INFO when the level is empty, as from docker-compose."""
    configure_logging("")
    assert logging.getLogger("app").level == logging.INFO
