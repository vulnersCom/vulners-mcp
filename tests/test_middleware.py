from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from prometheus_client import CollectorRegistry

from vulners_mcp.metrics.backends import (
    DualBackend,
    PrometheusBackend,
    StatsdBackend,
)
from vulners_mcp.metrics.config import MetricsConfig
from vulners_mcp.metrics.middleware import MetricsMiddleware


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_prom_mw(cfg: MetricsConfig) -> MetricsMiddleware:
    """Build a MetricsMiddleware with a fresh Prometheus registry (no HTTP)."""
    reg = CollectorRegistry()
    backend = PrometheusBackend(cfg, registry=reg, start_server=False)
    mw = MetricsMiddleware.__new__(MetricsMiddleware)
    mw._cfg = cfg
    mw._backend = backend
    return mw


def _make_both_mw(cfg: MetricsConfig) -> MetricsMiddleware:
    """Build a MetricsMiddleware with Prometheus + mocked StatsD."""
    reg = CollectorRegistry()
    prom = PrometheusBackend(cfg, registry=reg, start_server=False)
    with patch("statsd.StatsClient"):
        sd = StatsdBackend(cfg)
    mw = MetricsMiddleware.__new__(MetricsMiddleware)
    mw._cfg = cfg
    mw._backend = DualBackend([prom, sd])
    return mw


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def prom_mw():
    return _make_prom_mw(MetricsConfig.prometheus_only())


@pytest.fixture
def statsd_mw():
    cfg = MetricsConfig.statsd_only()
    with patch("statsd.StatsClient"):
        return MetricsMiddleware(cfg)


@pytest.fixture
def both_mw():
    return _make_both_mw(MetricsConfig.both())


@pytest.fixture
def disabled_mw():
    return MetricsMiddleware(MetricsConfig.disabled())


# ── Prometheus ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_prom_success_increments_counter(prom_mw):
    reg = prom_mw._backend._registry

    ctx = MagicMock()
    ctx.message.name = "add"
    await prom_mw.on_call_tool(ctx, AsyncMock(return_value="ok"))
    val = reg.get_sample_value(
        "mcp_tool_calls_total", {"tool_name": "add", "status": "success"}
    )
    assert val == 1.0


@pytest.mark.asyncio
async def test_prom_error_increments_error_counter(prom_mw):
    reg = prom_mw._backend._registry

    ctx = MagicMock()
    ctx.message.name = "broken"
    with pytest.raises(ValueError):
        await prom_mw.on_call_tool(ctx, AsyncMock(side_effect=ValueError("oops")))
    assert (
        reg.get_sample_value(
            "mcp_tool_errors_total",
            {"tool_name": "broken", "error_type": "ValueError"},
        )
        == 1.0
    )


# ── StatsD ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_statsd_tool_call_emitted(statsd_mw):
    ctx = MagicMock()
    ctx.message.name = "add"
    await statsd_mw.on_call_tool(ctx, AsyncMock(return_value="ok"))
    c = statsd_mw._backend._client
    c.incr.assert_called_once_with("tool.add.calls.success", rate=1.0)
    c.timing.assert_called_once()


# ── Both backends ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_both_backends_receive_event(both_mw):
    assert isinstance(both_mw._backend, DualBackend)
    assert len(both_mw._backend._backends) == 2

    ctx = MagicMock()
    ctx.message.name = "add"
    await both_mw.on_call_tool(ctx, AsyncMock(return_value="ok"))

    # Prometheus counter updated
    prom_backend = both_mw._backend._backends[0]
    val = prom_backend._registry.get_sample_value(
        "mcp_tool_calls_total", {"tool_name": "add", "status": "success"}
    )
    assert val == 1.0

    # StatsD client called
    sd_backend = both_mw._backend._backends[1]
    sd_backend._client.incr.assert_called_once_with("tool.add.calls.success", rate=1.0)


# ── Disabled ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_disabled_passes_through_untouched(disabled_mw):
    ctx = MagicMock()
    ctx.message.name = "add"
    call_next = AsyncMock(return_value="passthrough")
    result = await disabled_mw.on_call_tool(ctx, call_next)
    assert result == "passthrough"
    call_next.assert_awaited_once()


# ── Config ─────────────────────────────────────────────────────────────────────


def test_env_overrides_defaults(monkeypatch):
    monkeypatch.setenv("MCP_METRICS_MODE", "statsd")
    monkeypatch.setenv("MCP_METRICS_STATSD_HOST", "10.0.0.5")
    monkeypatch.setenv("MCP_METRICS_STATSD_SAMPLE_RATE", "0.25")
    cfg = MetricsConfig.from_env()
    assert cfg.mode == "statsd"
    assert cfg.statsd.host == "10.0.0.5"
    assert cfg.statsd.sample_rate == 0.25


def test_programmatic_config_ignores_env(monkeypatch):
    monkeypatch.setenv("MCP_METRICS_MODE", "prometheus")
    cfg = MetricsConfig.statsd_only(host="explicit.host")
    assert cfg.mode == "statsd"
    assert cfg.statsd.host == "explicit.host"


def test_per_backend_disable(monkeypatch):
    monkeypatch.setenv("MCP_METRICS_PROM_ENABLED", "false")
    monkeypatch.setenv("MCP_METRICS_MODE", "both")
    cfg = MetricsConfig.from_env()
    assert cfg.prometheus.enabled is False
    assert cfg.statsd.enabled is True


# ── URI normalisation ──────────────────────────────────────────────────────────


def test_normalise_uri_strips_uuids():
    from vulners_mcp.metrics.backends import normalise_uri

    assert (
        normalise_uri("/items/550e8400-e29b-41d4-a716-446655440000/detail")
        == "/items/{uuid}/detail"
    )


def test_normalise_uri_strips_numeric_ids():
    from vulners_mcp.metrics.backends import normalise_uri

    assert normalise_uri("/users/42/posts/99") == "/users/{id}/posts/{id}"


def test_normalise_uri_strips_query_string():
    from vulners_mcp.metrics.backends import normalise_uri

    assert normalise_uri("/items/123?page=2") == "/items/{id}"
