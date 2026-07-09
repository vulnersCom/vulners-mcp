"""Tests for ``vulners_mcp.logging_utils.configure_logging``.

Nothing in the app otherwise calls ``logging.basicConfig``/``dictConfig`` --
``uvicorn.run`` only configures its own ``uvicorn.*`` loggers -- so every
``vulners_mcp.*`` logger inherits the interpreter default (root at WARNING)
and every ``.info()`` call is silently dropped unless something configures
the package logger explicitly. These tests prove ``configure_logging()``
fixes that, without relying on ``caplog`` (which would install its own
handler/level and mask a broken ``configure_logging()``).
"""

from __future__ import annotations

import logging

from vulners_mcp.logging_utils import configure_logging


class _RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def test_configure_logging_makes_info_records_reach_a_handler() -> None:
    """A child ``vulners_mcp.*`` logger's INFO record is actually handled.

    The probe handler is attached directly to the child logger and never
    touches its level -- whether the record reaches it depends entirely on
    the *effective* level, which only becomes INFO if ``configure_logging()``
    set it on an ancestor (real app entrypoints only ever call
    ``getLogger("vulners_mcp.<module>")``, never set a level themselves).
    """
    child_logger = logging.getLogger("vulners_mcp.test_logging_config")
    probe = _RecordingHandler()
    child_logger.addHandler(probe)
    try:
        configure_logging()
        child_logger.info("hello %s", "world")
    finally:
        child_logger.removeHandler(probe)

    assert any(r.getMessage() == "hello world" for r in probe.records)


def test_configure_logging_is_idempotent() -> None:
    """Calling it repeatedly must not keep adding handlers."""
    package_logger = logging.getLogger("vulners_mcp")

    configure_logging()
    handler_count = len(package_logger.handlers)
    assert handler_count >= 1

    configure_logging()
    configure_logging()

    assert len(package_logger.handlers) == handler_count
