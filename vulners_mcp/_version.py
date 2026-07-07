# vulners_mcp/_version.py
"""Single source of truth for the package version, resolved without hardcoding."""

from __future__ import annotations


def _detect_version() -> str:
    """Resolve the package version.

    Order of precedence:
    1. Installed distribution metadata (``pip install .`` / PyPI wheel).
    2. ``pyproject.toml`` next to the package — the canonical source.
       The Dockerfile copies ``pyproject.toml`` into the image but installs deps
       with ``--no-root``, so distribution metadata is absent there; reading the
       manifest keeps the reported version honest in the container too.
    3. ``"0.0.0"`` as a last resort so import never fails.
    """
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("vulners-mcp")
        except PackageNotFoundError:
            pass
    except Exception:  # pragma: no cover - defensive
        pass

    try:
        import tomllib
        from pathlib import Path

        pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        with pyproject.open("rb") as fh:
            return tomllib.load(fh)["project"]["version"]
    except Exception:  # pragma: no cover - defensive
        return "0.0.0"


__version__ = _detect_version()
