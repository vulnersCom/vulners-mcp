# syntax=docker/dockerfile:1
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VERSION=2.2.0 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1

WORKDIR /srv

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install "poetry==${POETRY_VERSION}"

# deps layer
COPY pyproject.toml poetry.lock* ./
RUN poetry install --no-root --only main --no-ansi

# app layer
COPY app ./app

# non-root
RUN useradd -u 10001 -m appuser
USER appuser

EXPOSE 8000

# Start the FastMCP server (Streamable HTTP at /mcp/)
CMD ["python", "-m", "app.server"]
