from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .settings import MetricsSettings

log = logging.getLogger(__name__)

# -------------------- URI normalisation --------------------

_UUID_RE = re.compile(
    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)
_ID_RE = re.compile(r"/\d+")


def normalise_uri(uri: str) -> str:
    """Collapse high-cardinality URI segments into placeholders.

    * UUIDs  → ``{uuid}``
    * Numeric IDs (``/123``) → ``{id}``
    * Query strings are stripped entirely.
    """
    uri = _UUID_RE.sub("/{uuid}", uri)
    uri = _ID_RE.sub("/{id}", uri)
    return uri.split("?")[0]


# -------------------- Abstract base --------------------


class MetricsBackend(ABC):
    """Abstract interface that every metrics backend must implement.

    Each method corresponds to an MCP event type.  Implementations must
    be **synchronous** and **non-blocking** — the middleware calls them
    from an ``async`` context without ``await``.
    """

    @abstractmethod
    def record_tool_call(self, tool: str, status: str, elapsed: float) -> None:
        """Record a tool invocation with its outcome and wall-clock time."""

    @abstractmethod
    def record_tool_error(self, tool: str, error_type: str) -> None:
        """Record a tool error, keyed by exception class name."""

    @abstractmethod
    def record_resource_read(self, uri: str, status: str, elapsed: float) -> None:
        """Record a resource-read attempt with its outcome and latency."""

    @abstractmethod
    def record_prompt_call(self, prompt: str, status: str) -> None:
        """Record a prompt retrieval attempt."""

    @abstractmethod
    def record_message(self, msg_type: str) -> None:
        """Record any MCP message, keyed by JSON-RPC message class name."""

    @abstractmethod
    def session_inc(self) -> None:
        """Increment the active-session gauge."""

    @abstractmethod
    def session_dec(self) -> None:
        """Decrement the active-session gauge."""

    def close(self) -> None:
        """Release resources held by the backend (sockets, files, etc.)."""


# -------------------- Prometheus backend --------------------


class PrometheusBackend(MetricsBackend):
    """HTTP ``/metrics`` scrape endpoint (pull model).

    Registers counters, histograms and gauges in a
    ``prometheus_client`` registry and optionally starts a lightweight
    HTTP server for scraping.

    Requires: ``pip install prometheus_client``

    Args:
        cfg: Root metrics configuration.
        registry: Custom ``CollectorRegistry``.  When *None* the global
            ``REGISTRY`` is used.
        start_server: Start the built-in HTTP server on
            ``cfg.prometheus.host:cfg.prometheus.port``.  Set to
            ``False`` in tests or when the registry is scraped by an
            external ASGI/WSGI app.
    """

    def __init__(
        self,
        cfg: MetricsSettings,
        *,
        registry: object | None = None,
        start_server: bool = True,
    ) -> None:
        try:
            from prometheus_client import (
                GC_COLLECTOR,
                PLATFORM_COLLECTOR,
                PROCESS_COLLECTOR,
                REGISTRY,
                CollectorRegistry,
                Counter,
                Gauge,
                Histogram,
                start_http_server,
            )
        except ImportError as exc:
            raise RuntimeError(
                "prometheus_client is not installed. Run: pip install prometheus_client"
            ) from exc

        p = cfg.prefix
        pc = cfg.prometheus

        if registry is not None:
            reg: CollectorRegistry = registry  # type: ignore[assignment]
        else:
            reg = REGISTRY
            if not pc.include_process_metrics:
                for col in (
                    PROCESS_COLLECTOR,
                    PLATFORM_COLLECTOR,
                    GC_COLLECTOR,
                ):
                    try:
                        reg.unregister(col)
                    except Exception:
                        pass

        self._registry = reg

        self._tool_calls = Counter(
            f"{p}_tool_calls_total",
            "Tool invocations",
            ["tool_name", "status"],
            registry=reg,
        )
        self._tool_errors = Counter(
            f"{p}_tool_errors_total",
            "Tool errors by exception type",
            ["tool_name", "error_type"],
            registry=reg,
        )
        self._tool_latency = Histogram(
            f"{p}_tool_duration_seconds",
            "Tool execution latency",
            ["tool_name"],
            buckets=pc.latency_buckets,
            registry=reg,
        )
        self._resource_reads = Counter(
            f"{p}_resource_reads_total",
            "Resource read attempts",
            ["uri", "status"],
            registry=reg,
        )
        self._resource_latency = Histogram(
            f"{p}_resource_read_duration_seconds",
            "Resource read latency",
            ["uri"],
            buckets=pc.latency_buckets,
            registry=reg,
        )
        self._prompt_calls = Counter(
            f"{p}_prompt_calls_total",
            "Prompt retrieval attempts",
            ["prompt_name", "status"],
            registry=reg,
        )
        self._messages = Counter(
            f"{p}_messages_total",
            "All MCP messages by type",
            ["message_type"],
            registry=reg,
        )
        self._sessions = Gauge(
            f"{p}_active_sessions", "Active MCP sessions", registry=reg
        )

        if start_server:
            start_http_server(pc.port, addr=pc.host, registry=reg)

    def record_tool_call(self, tool: str, status: str, elapsed: float) -> None:
        self._tool_calls.labels(tool_name=tool, status=status).inc()
        self._tool_latency.labels(tool_name=tool).observe(elapsed)

    def record_tool_error(self, tool: str, error_type: str) -> None:
        self._tool_errors.labels(tool_name=tool, error_type=error_type).inc()

    def record_resource_read(self, uri: str, status: str, elapsed: float) -> None:
        self._resource_reads.labels(uri=uri, status=status).inc()
        self._resource_latency.labels(uri=uri).observe(elapsed)

    def record_prompt_call(self, prompt: str, status: str) -> None:
        self._prompt_calls.labels(prompt_name=prompt, status=status).inc()

    def record_message(self, msg_type: str) -> None:
        self._messages.labels(message_type=msg_type).inc()

    def session_inc(self) -> None:
        self._sessions.inc()

    def session_dec(self) -> None:
        self._sessions.dec()


# -------------------- StatsD backend --------------------


class StatsdBackend(MetricsBackend):
    """UDP push backend for StatsD-compatible aggregators.

    Sends counters, timers (ms) and gauges over UDP.  Works with
    Graphite, Telegraf, DogStatsD, Okagent, and any other
    StatsD-compatible receiver.

    Requires: ``pip install statsd``

    Args:
        cfg: Root metrics configuration.
    """

    def __init__(self, cfg: MetricsSettings) -> None:
        try:
            import statsd as _statsd  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError(
                "statsd is not installed. Run: pip install statsd"
            ) from exc

        sc = cfg.statsd
        self._rate = sc.sample_rate
        self._client = _statsd.StatsClient(
            host=sc.host,
            port=sc.port,
            prefix=cfg.prefix,
            maxudpsize=sc.maxudpsize,
            ipv6=sc.ipv6,
        )

    def record_tool_call(self, tool: str, status: str, elapsed: float) -> None:
        self._client.incr(f"tool.{tool}.calls.{status}", rate=self._rate)
        self._client.timing(
            f"tool.{tool}.duration", int(elapsed * 1000), rate=self._rate
        )

    def record_tool_error(self, tool: str, error_type: str) -> None:
        self._client.incr(f"tool.{tool}.errors.{error_type}", rate=self._rate)

    def record_resource_read(self, uri: str, status: str, elapsed: float) -> None:
        safe = uri.replace("/", ".").strip(".") or "root"
        self._client.incr(f"resource.{safe}.{status}", rate=self._rate)
        self._client.timing(
            f"resource.{safe}.duration", int(elapsed * 1000), rate=self._rate
        )

    def record_prompt_call(self, prompt: str, status: str) -> None:
        self._client.incr(f"prompt.{prompt}.{status}", rate=self._rate)

    def record_message(self, msg_type: str) -> None:
        self._client.incr(f"messages.{msg_type}", rate=self._rate)

    def session_inc(self) -> None:
        self._client.gauge("active_sessions", 1, delta=True)

    def session_dec(self) -> None:
        self._client.gauge("active_sessions", -1, delta=True)

    def close(self) -> None:
        sock = getattr(self._client, "_sock", None)
        if sock:
            sock.close()


# -------------------- Dual backend --------------------


class DualBackend(MetricsBackend):
    """Fan-out wrapper that dispatches every event to multiple backends.

    Used when ``MCP_METRICS_MODE=both``.  If one backend raises, the
    exception is logged and the remaining backends still receive the
    event.
    """

    def __init__(self, backends: list[MetricsBackend]) -> None:
        self._backends = backends

    def _fan(self, method: str, *args: object, **kwargs: object) -> None:
        for b in self._backends:
            try:
                getattr(b, method)(*args, **kwargs)
            except Exception as exc:
                log.error("Backend %s.%s failed: %s", type(b).__name__, method, exc)

    def record_tool_call(self, tool: str, status: str, elapsed: float) -> None:
        self._fan("record_tool_call", tool, status, elapsed)

    def record_tool_error(self, tool: str, error_type: str) -> None:
        self._fan("record_tool_error", tool, error_type)

    def record_resource_read(self, uri: str, status: str, elapsed: float) -> None:
        self._fan("record_resource_read", uri, status, elapsed)

    def record_prompt_call(self, prompt: str, status: str) -> None:
        self._fan("record_prompt_call", prompt, status)

    def record_message(self, msg_type: str) -> None:
        self._fan("record_message", msg_type)

    def session_inc(self) -> None:
        self._fan("session_inc")

    def session_dec(self) -> None:
        self._fan("session_dec")

    def close(self) -> None:
        for b in self._backends:
            b.close()


# -------------------- Factory --------------------


def build_backend(cfg: MetricsSettings) -> MetricsBackend | None:
    """Instantiate and return the active backend(s) from *cfg*.

    Resolution order:

    1. If ``cfg.enabled`` is ``False`` or mode is ``"none"`` — return ``None``.
    2. Collect all individually enabled sub-backends.
    3. If zero remain — return ``None``.
    4. If one remains — return it directly (no ``DualBackend`` wrapper).
    5. If multiple — wrap in ``DualBackend``.
    """
    if not cfg.enabled or cfg.mode == "none":
        log.info("metrics: disabled (enabled=%s mode=%s)", cfg.enabled, cfg.mode)
        return None

    active: list[MetricsBackend] = []

    want_prom = cfg.mode in ("both", "prometheus") and cfg.prometheus.enabled
    want_statsd = cfg.mode in ("both", "statsd") and cfg.statsd.enabled

    if want_prom:
        try:
            active.append(PrometheusBackend(cfg))
            log.info(
                "metrics: Prometheus backend active on %s:%d/metrics",
                cfg.prometheus.host,
                cfg.prometheus.port,
            )
        except RuntimeError as exc:
            log.error("metrics: Prometheus backend failed to start — %s", exc)

    if want_statsd:
        try:
            active.append(StatsdBackend(cfg))
            log.info(
                "metrics: StatsD backend active -> %s:%d",
                cfg.statsd.host,
                cfg.statsd.port,
            )
        except RuntimeError as exc:
            log.error("metrics: StatsD backend failed to start — %s", exc)

    if not active:
        log.warning("metrics: no backends could be initialised")
        return None

    if len(active) == 1:
        return active[0]

    log.info("metrics: DualBackend active (%d backends)", len(active))
    return DualBackend(active)
