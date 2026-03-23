from __future__ import annotations

import os
import typing
from dataclasses import dataclass, field
from typing import Literal

# -------------------- Types --------------------

Mode = Literal["both", "prometheus", "statsd", "none"]


# -------------------- Env helpers --------------------


def _bool(key: str, default: bool) -> bool:
    v = os.getenv(key)
    return default if v is None else v.strip().lower() in ("1", "true", "yes")


def _int(key: str, default: int) -> int:
    v = os.getenv(key)
    return int(v) if v is not None else default


def _str(key: str, default: str) -> str:
    return os.getenv(key, default)


def _float(key: str, default: float) -> float:
    v = os.getenv(key)
    return float(v) if v is not None else default


# -------------------- Sub-configs --------------------


@dataclass
class PrometheusConfig:
    """Prometheus scrape-endpoint backend settings.

    Every field can be overridden via an ``MCP_METRICS_PROM_*`` env var.

    Attributes:
        enabled: Activate this backend.  Default ``False`` (honoured only
            when the root ``mode`` includes ``"prometheus"``).
        port: TCP port for the ``/metrics`` HTTP endpoint.
        host: Bind address.  Keep ``127.0.0.1`` unless the collector
            runs on a different host.
        latency_buckets: Histogram bucket boundaries (seconds) for
            tool and resource-read latency.
        include_process_metrics: Expose default ``process_*``,
            ``python_*`` and ``gc_*`` collectors.
    """

    enabled: bool = field(
        default_factory=lambda: _bool("MCP_METRICS_PROM_ENABLED", False)
    )
    port: int = field(default_factory=lambda: _int("MCP_METRICS_PROM_PORT", 9100))
    host: str = field(
        default_factory=lambda: _str("MCP_METRICS_PROM_HOST", "127.0.0.1")
    )
    latency_buckets: tuple[float, ...] = (
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1,
        2.5,
        5,
        10,
    )
    include_process_metrics: bool = field(
        default_factory=lambda: _bool("MCP_METRICS_PROM_PROCESS_METRICS", False)
    )


@dataclass
class StatsdConfig:
    """StatsD UDP backend settings.

    Every field can be overridden via an ``MCP_METRICS_STATSD_*`` env var.

    Attributes:
        enabled: Activate this backend.  Default ``False`` (honoured only
            when the root ``mode`` includes ``"statsd"``).
        host: StatsD / aggregator host.
        port: StatsD UDP port.
        maxudpsize: Max UDP payload in bytes.  Keep <= 1432 to avoid
            IP fragmentation.
        ipv6: Use an IPv6 socket.
        sample_rate: Sampling rate ``0.0``--``1.0``.  Lower values reduce
            UDP traffic at the cost of counter precision.
    """

    enabled: bool = field(
        default_factory=lambda: _bool("MCP_METRICS_STATSD_ENABLED", False)
    )
    host: str = field(
        default_factory=lambda: _str("MCP_METRICS_STATSD_HOST", "127.0.0.1")
    )
    port: int = field(default_factory=lambda: _int("MCP_METRICS_STATSD_PORT", 8125))
    maxudpsize: int = field(
        default_factory=lambda: _int("MCP_METRICS_STATSD_MAXUDP", 512)
    )
    ipv6: bool = field(default_factory=lambda: _bool("MCP_METRICS_STATSD_IPV6", False))
    sample_rate: float = field(
        default_factory=lambda: _float("MCP_METRICS_STATSD_SAMPLE_RATE", 1.0)
    )


# -------------------- Root config --------------------


@dataclass
class MetricsSettings:
    """Root configuration for :class:`MetricsMiddleware`.

    Disabled by default (``mode="none"``, ``enabled=False``).
    Set ``MCP_METRICS_MODE`` to ``"prometheus"`` or ``"statsd"`` and
    ``MCP_METRICS_ENABLED=true`` to activate the backend you need.

    Resolution priority: constructor kwargs > env vars > built-in defaults.

    Attributes:
        mode: Active backend — ``"prometheus"``, ``"statsd"``,
            ``"both"``, or ``"none"``.
        prefix: String prepended to every metric name
            (``{prefix}_tool_calls_total``).
        enabled: Global kill-switch.  ``False`` disables all backends
            regardless of *mode*.
        normalise_uris: Replace UUIDs and numeric IDs in resource URI
            labels with ``{uuid}`` / ``{id}`` placeholders to prevent
            high-cardinality explosions.
        prometheus: Prometheus-specific settings.
        statsd: StatsD-specific settings.
    """

    mode: Mode = field(
        default_factory=lambda: typing.cast(Mode, _str("MCP_METRICS_MODE", "none"))
    )
    prefix: str = field(default_factory=lambda: _str("MCP_METRICS_PREFIX", "mcp"))
    enabled: bool = field(default_factory=lambda: _bool("MCP_METRICS_ENABLED", False))
    normalise_uris: bool = field(
        default_factory=lambda: _bool("MCP_METRICS_NORMALISE_URIS", True)
    )
    prometheus: PrometheusConfig = field(default_factory=PrometheusConfig)
    statsd: StatsdConfig = field(default_factory=StatsdConfig)

    # -------------------- Convenience constructors --------------------

    @classmethod
    def from_env(cls) -> MetricsSettings:
        """Build entirely from ``MCP_METRICS_*`` environment variables."""
        return cls()

    @classmethod
    def both(
        cls,
        *,
        prefix: str = "mcp",
        prom_port: int = 9100,
        prom_host: str = "127.0.0.1",
        statsd_host: str = "127.0.0.1",
        statsd_port: int = 8125,
    ) -> MetricsSettings:
        """Enable Prometheus **and** StatsD simultaneously."""
        return cls(
            mode="both",
            enabled=True,
            prefix=prefix,
            prometheus=PrometheusConfig(port=prom_port, host=prom_host),
            statsd=StatsdConfig(host=statsd_host, port=statsd_port),
        )

    @classmethod
    def prometheus_only(
        cls,
        port: int = 9100,
        host: str = "127.0.0.1",
        prefix: str = "mcp",
    ) -> MetricsSettings:
        """Enable the Prometheus backend only."""
        return cls(
            mode="prometheus",
            enabled=True,
            prefix=prefix,
            prometheus=PrometheusConfig(port=port, host=host),
            statsd=StatsdConfig(enabled=False),
        )

    @classmethod
    def statsd_only(
        cls,
        host: str = "127.0.0.1",
        port: int = 8125,
        prefix: str = "mcp",
    ) -> MetricsSettings:
        """Enable the StatsD backend only."""
        return cls(
            mode="statsd",
            enabled=True,
            prefix=prefix,
            prometheus=PrometheusConfig(enabled=False),
            statsd=StatsdConfig(host=host, port=port),
        )

    @classmethod
    def disabled(cls) -> MetricsSettings:
        """Return a config that disables all metrics collection."""
        return cls(mode="none", enabled=False)
