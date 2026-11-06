"""Unit test cases for showing roles in the OpenAPI document."""

import pytest
from fastapi import FastAPI

from app.authorization import document_roles, require_roles
from app.models import Role


@pytest.fixture
def api() -> FastAPI:
    """Create a small app with and without role checks."""
    api = FastAPI()

    @api.post("/things", dependencies=[require_roles(Role.EVENT_ADMIN, Role.ADMIN)])
    async def create_thing() -> None:
        """Create a thing."""

    @api.delete("/things", dependencies=[require_roles(Role.ADMIN)])
    async def delete_things() -> None:
        pass

    @api.get("/things")
    async def get_things() -> None:
        """Get things."""

    document_roles(api)
    return api


@pytest.mark.unit
def test_document_roles_adds_roles_to_protected_operations(api: FastAPI) -> None:
    """Should list the roles in declared order, and document 401 and 403."""
    operation = api.openapi()["paths"]["/things"]["post"]

    assert operation["security"] == [{"HTTPBearer": ["event-admin", "admin"]}]
    assert operation["description"] == (
        "Create a thing.\n\n**Roles:** `event-admin`, `admin`"
    )
    assert operation["responses"]["401"]["description"] == "Missing or invalid token"
    assert operation["responses"]["403"]["description"] == (
        "Operation forbidden: requires one of the roles event-admin, admin"
    )


@pytest.mark.unit
def test_document_roles_without_docstring(api: FastAPI) -> None:
    """Should use the roles as the whole description when there is none."""
    operation = api.openapi()["paths"]["/things"]["delete"]

    assert operation["description"] == "**Roles:** `admin`"


@pytest.mark.unit
def test_document_roles_leaves_open_operations_alone(api: FastAPI) -> None:
    """Should not change operations without a role check."""
    operation = api.openapi()["paths"]["/things"]["get"]

    assert "security" not in operation
    assert operation["description"] == "Get things."
    assert "403" not in operation["responses"]


@pytest.mark.unit
def test_document_roles_generates_the_schema_once(api: FastAPI) -> None:
    """Should return the cached schema, without adding the roles twice."""
    first = api.openapi()
    second = api.openapi()

    assert second is first
    assert second["paths"]["/things"]["delete"]["description"] == ("**Roles:** `admin`")
