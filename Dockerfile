# syntax=docker/dockerfile:1
FROM python:3.14-slim

LABEL io.modelcontextprotocol.server.name="io.github.vulnersCom/vulners-mcp"
ENV FASTMCP_HOST=0.0.0.0
ENV FASTMCP_PORT=8000

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VERSION=2.2.0 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1

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

# Transport is chosen at runtime by MCP_TRANSPORT_MODE (default: stdio).
# In HTTP mode this boots uvicorn against the composed ASGI app
# (vulners_mcp.asgi:app, Streamable HTTP at /mcp) -- see vulners_mcp/__init__.py.
CMD ["python", "-m", "vulners_mcp"]
