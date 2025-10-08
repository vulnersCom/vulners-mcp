# syntax=docker/dockerfile:1
FROM python:3.13-slim

LABEL io.modelcontextprotocol.server.name="io.github.vulnersCom/vulners-mcp"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VERSION=2.2.0 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1 \
    FAST_MCP_HOST=0.0.0.0

WORKDIR /app

RUN pip install "poetry==${POETRY_VERSION}"

# deps layer
COPY pyproject.toml poetry.lock* ./
RUN poetry install --no-root --only main --no-ansi

# app layer
COPY vulners_mcp ./vulners_mcp

# non-root
RUN useradd -u 10001 -m appuser
USER appuser

EXPOSE 8000

# Start the FastMCP server (Streamable HTTP at /mcp/)
CMD ["python", "-m", "vulners_mcp"]
