FROM python:3.11

RUN mkdir -p /app
WORKDIR /app

RUN pip install --upgrade pip
RUN pip install "poetry==1.7.1"
COPY poetry.lock pyproject.toml /app/

# Project initialization:
RUN poetry config virtualenvs.create false \
  && poetry install --no-dev --no-interaction --no-ansi

ADD user_service /app/user_service

EXPOSE 8080

CMD gunicorn "user_service:create_app"  --config=user_service/gunicorn_config.py --worker-class aiohttp.GunicornWebWorker
