# syntax=docker/dockerfile:1

# --- build stage: install dependencies ---
FROM python:3.14.4-slim-trixie AS build

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

# deps layer (cached unless pyproject.toml or uv.lock change)
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

# app layer
COPY README.md ./
COPY vulners_mcp ./vulners_mcp
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# --- run stage: minimal image ---
FROM python:3.14.4-slim-trixie

LABEL io.modelcontextprotocol.server.name="io.github.vulnersCom/vulners-mcp"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FASTMCP_HOST=0.0.0.0 \
    FASTMCP_PORT=8000

WORKDIR /app

# copy venv from build stage
COPY --from=build /app/.venv /app/.venv
COPY --from=build /app/vulners_mcp /app/vulners_mcp

ENV PATH="/app/.venv/bin:$PATH"

# non-root
RUN useradd -u 10001 -m appuser
USER appuser

EXPOSE 8000

CMD ["python", "-m", "vulners_mcp"]
