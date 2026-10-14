"""Observability middleware for the Vulners MCP server.

Instruments every MCP operation (tool calls, resource reads, prompts,
messages, sessions) and emits metrics to a **Prometheus** scrape endpoint
and/or a **StatsD** UDP sink.  Disabled by default — set
``MCP_METRICS_MODE=prometheus`` or ``MCP_METRICS_MODE=statsd`` to enable.
"""

from __future__ import annotations

from .middleware import MetricsMiddleware
from .settings import MetricsSettings

__all__ = ["MetricsSettings", "MetricsMiddleware"]
