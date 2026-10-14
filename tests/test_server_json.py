"""Drift guard for ``server.json`` (the MCP registry manifest).

``server.json`` was caught stuck at ``1.0.3`` while ``pyproject.toml`` (and
therefore the running server's reported version) had already moved on to
``1.13.0`` -- three numbers that are supposed to be one fact, silently out of
sync. This module pins all three together so that can't happen again
unnoticed, and checks the declared remote transport actually matches the
hosted Streamable HTTP endpoint.
"""

from __future__ import annotations

import json
from importlib.metadata import version as installed_version
from pathlib import Path

from vulners_mcp import discovery
from vulners_mcp.server import mcp

SERVER_JSON_PATH = Path(__file__).parent.parent / "server.json"


def _load_server_json() -> dict:
    return json.loads(SERVER_JSON_PATH.read_text())


def _package(data: dict, registry_type: str) -> dict:
    return next(p for p in data["packages"] if p["registryType"] == registry_type)


def test_server_json_version_matches_importlib_and_mcp_version() -> None:
    pkg_version = installed_version("vulners-mcp")
    data = _load_server_json()

    assert data["version"] == pkg_version
    assert _package(data, "pypi")["version"] == pkg_version
    assert mcp.version == pkg_version


def test_server_json_oci_image_tag_matches_the_version() -> None:
    """The release workflow pushes the image as ``ghcr.io/...:<version>``;
    the registry pulls exactly the tag named here to verify ownership."""
    data = _load_server_json()
    image, _, tag = _package(data, "oci")["identifier"].rpartition(":")

    assert image == "ghcr.io/vulnerscom/vulners-mcp"
    assert tag == data["version"]


def test_server_json_remote_matches_the_live_mcp_endpoint() -> None:
    data = _load_server_json()
    remotes = data.get("remotes")
    assert remotes, "server.json must declare the hosted streamable-http endpoint"

    remote = remotes[0]
    assert remote["type"] == "streamable-http"
    assert remote["url"] == discovery.MCP_ENDPOINT


def test_server_json_stdio_package_transport_is_stdio() -> None:
    """The pypi package and the Docker image (self-hosted / stdio use, see
    auth.md) are a different install path from the hosted remote above --
    they must keep declaring stdio, not the hosted transport."""
    data = _load_server_json()
    for package in data["packages"]:
        assert package["transport"]["type"] == "stdio", package["registryType"]


def test_readme_carries_the_mcp_name_for_pypi_verification() -> None:
    """The registry verifies the pypi package by finding ``mcp-name: <name>``
    in its PyPI description, which is this README."""
    readme = (SERVER_JSON_PATH.parent / "README.md").read_text()
    name = _load_server_json()["name"]

    assert f"<!-- mcp-name: {name} -->" in readme
