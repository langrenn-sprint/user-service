# user-service

Back-end service to administer users and login

Example of usage:

```Shell
% curl -H "Content-Type: application/json" \
  -X POST \
  --data '{"username":"admin","password":"passw123"}' \
  http://localhost:8080/login
% export ACCESS="" #token from response
% curl -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS" \
  -X POST \
  --data @tests/files/user.json \
  http://localhost:8080/users
% curl -H "Authorization: Bearer $ACCESS"  http://localhost:8080/users
```

## Architecture

Layers:

- views: routing functions, maps representations to/from model
- services: enforce validation, calls adapter-layer for storing/retrieving objects
- models: model-classes
- adapters: adapters to external services

## Running the API locally

Start the server locally:

```Shell
% poetry run adev runserver -p 8080 user_service
```

## Running the API in a wsgi-server (gunicorn)

```Shell
% poetry run gunicorn user_service:create_app --bind localhost:8080 --worker-class aiohttp.GunicornWebWorker
```

## Running the wsgi-server in Docker

To build and run the api in a Docker container:

```Shell
% docker build -t digdir/user-service:latest .
% docker run --env-file .env -p 8080:8080 -d digdir/user-service:latest
```

The easier way would be with docker-compose:

```Shell
docker-compose up --build
```

## Running tests

We use [pytest](https://docs.pytest.org/en/latest/) for contract testing.

To run linters, checkers and tests:

```Shel
% nox
```

To run tests with logging, do:

```Shell
% nox -s integration_tests -- --log-cli-level=DEBUG
```
