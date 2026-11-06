# user-service

Back-end service to administer users and login

Example of usage:

```Zsh
% curl -H "Content-Type: application/json" \
  -X POST \
  --data '{"username":"admin","password":"passw123"}' \
  http://localhost:8000/login
% export ACCESS="" #token from response
% curl -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS" \
  -X POST \
  --data @tests/files/user.json \
  http://localhost:8000/users
% curl -H "Authorization: Bearer $ACCESS"  http://localhost:8000/users
```

A token is valid for `JWT_EXP_DELTA_SECONDS`. Renew a valid token before it expires to get a new one with full lifetime:

```Zsh
% curl -H "Authorization: Bearer $ACCESS" -X POST http://localhost:8000/token/renew
```

The user is read again on renewal, so a deleted user gets `401` and a changed role is put in the new token. The token's `auth_time` claim (when the user logged in with password) is kept, and renewal is refused with `401` when it is older than `JWT_MAX_SESSION_SECONDS` (default 86400, i.e. 24 hours). Expired, invalid or missing tokens also get `401`.

## Users set their own password

Admin can create a user without password. The response has a one-time activation code, which admin passes on to the user, e.g. as a link in event-service-gui:

```Zsh
% curl -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS" \
  -X POST \
  --data '{"username":"ola@example.com","role":"event-admin"}' \
  http://localhost:8000/users
{"user_id":"…","code":"…","expires":"…"}
```

The user sets the password with the code. This needs no token, and the code can only be used once:

```Zsh
% curl -H "Content-Type: application/json" \
  -X POST \
  --data '{"code":"…","password":"at least 10 characters"}' \
  http://localhost:8000/activate
```

- The code is valid for `ACTIVATION_CODE_TTL_HOURS` (default 48). Only a hash of it is stored.
- An unknown, used or expired code gives `400`, and a password shorter than 10 characters gives `422`. The minimum length also applies when admin sets a password.
- A user without password cannot log in: `POST /login` gives `403`.
- `POST /users/{id}/activation` (admin) gives the user a new code, e.g. to reset a forgotten password. Earlier codes stop working, and a password the user has keeps working until the new one is set.
- `GET /users` shows whether each user is `activated`, and when a pending code expires. It never shows passwords or codes.
- Admin can still create a user with a password, as before. Existing users keep their passwords.

## Architecture

Layers:

- views: routing functions, maps representations to/from model
- services: enforce validation, calls adapter-layer for storing/retrieving objects
- models: model-classes
- adapters: adapters to external services

## Environment variables

To run the service locally, you need to supply a set of environment variables. A simple way to solve this is to supply a .env file in the root directory.

A minimal .env:

```Zsh
JWT_SECRET=secret
JWT_EXP_DELTA_SECONDS=3600
JWT_MAX_SESSION_SECONDS=86400
ADMIN_USERNAME=admin
ADMIN_PASSWORD=passw123
DB_USER=admin
DB_PASSWORD=admin
LOGGING_LEVEL=DEBUG
```

Optional: `ACTIVATION_CODE_TTL_HOURS` (default 48), how long an activation code is valid.

## Requirement for development

Install [uv](https://docs.astral.sh/uv/), e.g.:

```Zsh
% curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then install the dependencies:

```Zsh
% uv sync
```

## Running the API locally

Start the server locally:

```Zsh
% uv run --env-file .env fastapi dev
```

## Running the API in a wsgi-server (gunicorn)

```Zsh
% uv run --env-file .env uvicorn app:api --host 0.0.0.0 --port 8000 --workers 1 --log-config=logging.yaml
```

## Running the wsgi-server in Docker

To build and run the api in a Docker container:

```Zsh
% docker build -t ghcr.io/langrenn-sprint/user-service:latest .
% docker run --env-file .env -p 8000:8000 -d ghcr.io/langrenn-sprint/user-service:latest
```

The easier way would be with docker-compose:

```Zsh
docker compose up --build
```

## Running tests

We use [pytest](https://docs.pytest.org/en/latest/) for contract testing.

To run linters, checkers and tests:

```Zsh
% uv run poe release
```

To run tests with logging, do:

```Zsh
% uv run pytest -m integration -- --log-cli-level=DEBUG
```
