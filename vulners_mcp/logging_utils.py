"""Structured (key=value / logfmt-style) logging helpers for outbound Vulners API calls.

Kept intentionally small and dependency-free (stdlib ``logging`` only), so it
composes with whatever log shipper/formatter the deployment already uses.
"""

from __future__ import annotations

import hashlib
import logging

logger = logging.getLogger("vulners_mcp.client")


def key_fingerprint(api_key: str | None) -> str | None:
    """Return the first 8 hex chars of sha256(api_key), or ``None`` if no key.

    This is a one-way fingerprint only, useful for correlating "same caller"
    across log lines — the raw key is never logged or returned.
    """
    if not api_key:
        return None
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:8]


def log_upstream_call(
    *,
    request_id: str,
    method: str,
    path: str,
    status: int | None,
    duration_ms: float,
    auth_mode: str,
    key_fp: str | None,
    result_size: int | None,
    attempt: int,
) -> None:
    """Emit one structured log line describing a single attempt of an upstream call.

    Fields (all logged as ``key=value`` tokens in the message, never as a raw
    secret): ``request_id`` (one uuid per logical tool call, shared across
    retry attempts), ``method``, ``path``, ``status`` (``-`` if the attempt
    never got an HTTP response, e.g. a connect error), ``duration_ms``,
    ``auth_mode`` (``"keyed"`` or ``"anonymous"``), ``key_fp`` (see
    :func:`key_fingerprint`), ``result_size`` (bytes in the response body, if
    any), and ``attempt`` (1-based).
    """
    logger.info(
        "vulners_upstream_call request_id=%s method=%s path=%s status=%s "
        "duration_ms=%.1f auth_mode=%s key_fp=%s result_size=%s attempt=%s",
        request_id,
        method,
        path,
        status if status is not None else "-",
        duration_ms,
        auth_mode,
        key_fp if key_fp is not None else "-",
        result_size if result_size is not None else "-",
        attempt,
    )
