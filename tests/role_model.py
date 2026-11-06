"""The role model for user-service, used by the contract tests.

See langrenn-sprint/event-service-gui#215. Only admin may read and change
users. Login, token renewal and authorize are open to every user.
"""

ADMIN = "admin"
EVENT_ADMIN = "event-admin"
RESULT_ADMIN = "result-admin"
CONTESTANT_ADMIN = "contestant-admin"

ROLES = [ADMIN, EVENT_ADMIN, RESULT_ADMIN, CONTESTANT_ADMIN]
# Roles that no longer exist, and cannot be given to a user:
REMOVED_ROLES = ["user-admin", "race-result", "race-office"]

ADMIN_ONLY = {ADMIN}

ACCESS: dict[tuple[str, str], set[str]] = {
    ("GET", "/users"): ADMIN_ONLY,
    ("POST", "/users"): ADMIN_ONLY,
    ("GET", "/users/{user_id}"): ADMIN_ONLY,
    ("PUT", "/users/{user_id}"): ADMIN_ONLY,
    ("DELETE", "/users/{user_id}"): ADMIN_ONLY,
}


def access_cases(roles: list[str]) -> list[tuple[str, str, str, bool]]:
    """Return (method, path, role, allowed) for every operation and role."""
    return [
        (method, path, role, role in allowed)
        for (method, path), allowed in ACCESS.items()
        for role in roles
    ]
