from __future__ import annotations

import logging
import time
from typing import Any

from fastmcp.server.middleware import Middleware, MiddlewareContext

from .backends import MetricsBackend, build_backend, normalise_uri
from .settings import MetricsSettings

logger = logging.getLogger(__name__)


class MetricsMiddleware(Middleware):
    """FastMCP middleware that instruments every MCP operation.

    Disabled by default.  Enable via env vars or an explicit config::

        # Via environment (set before server start):
        #   MCP_METRICS_ENABLED=true
        #   MCP_METRICS_MODE=prometheus   # or "statsd" / "both"

        from fastmcp import FastMCP
        from vulners_mcp.metrics import MetricsMiddleware, MetricsSettings

        mcp = FastMCP("my-server")
        mcp.add_middleware(MetricsMiddleware())          # reads MCP_METRICS_*
        mcp.add_middleware(MetricsMiddleware(             # explicit
            MetricsSettings.prometheus_only(port=9100),
        ))

    Args:
        config: Explicit configuration.  When *None*,
            :meth:`MetricsSettings.from_env` is used.
    """

    def __init__(self, config: MetricsSettings | None = None) -> None:
        self._cfg = config or MetricsSettings.from_env()
        self._backend: MetricsBackend | None = build_backend(self._cfg)

    # -------------------- Internal helpers --------------------

    def _uri(self, raw: str) -> str:
        return normalise_uri(raw) if self._cfg.normalise_uris else raw

    # -------------------- on_message --------------------

    async def on_message(
        self,
        context: MiddlewareContext[Any],
        call_next: Any,
    ) -> Any:
        if self._backend:
            self._backend.record_message(type(context.message).__name__)
        return await call_next(context)

    # -------------------- on_initialize --------------------

    async def on_initialize(
        self,
        context: MiddlewareContext[Any],
        call_next: Any,
    ) -> Any:
        if self._backend:
            self._backend.session_inc()
        try:
            return await call_next(context)
        except Exception:
            if self._backend:
                self._backend.session_dec()
            raise

    # -------------------- on_call_tool --------------------

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: Any,
    ) -> Any:
        if not self._backend:
            return await call_next(context)

        tool_name = getattr(context.message, "name", "unknown")
        start = time.monotonic()
        status = "success"

        try:
            return await call_next(context)
        except Exception as exc:
            status = "error"
            self._backend.record_tool_error(tool_name, type(exc).__name__)
            logger.exception("tool=%s error=%s", tool_name, type(exc).__name__)
            raise
        finally:
            elapsed = time.monotonic() - start
            self._backend.record_tool_call(tool_name, status, elapsed)
            logger.debug(
                "tool=%s status=%s duration=%.4fs",
                tool_name,
                status,
                elapsed,
            )

    # -------------------- on_read_resource --------------------

    async def on_read_resource(
        self,
        context: MiddlewareContext[Any],
        call_next: Any,
    ) -> Any:
        if not self._backend:
            return await call_next(context)

        uri = self._uri(str(getattr(context.message, "uri", "unknown")))
        start = time.monotonic()
        status = "success"

        try:
            return await call_next(context)
        except Exception:
            status = "error"
            raise
        finally:
            self._backend.record_resource_read(uri, status, time.monotonic() - start)

    # -------------------- on_get_prompt --------------------

    async def on_get_prompt(
        self,
        context: MiddlewareContext[Any],
        call_next: Any,
    ) -> Any:
        if not self._backend:
            return await call_next(context)

        prompt_name = getattr(context.message, "name", "unknown")
        status = "success"

        try:
            return await call_next(context)
        except Exception:
            status = "error"
            raise
        finally:
            self._backend.record_prompt_call(prompt_name, status)
