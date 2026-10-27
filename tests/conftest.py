"""Pytest fixtures for Web Guard."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"


def _install_source_package() -> None:
    """Load the flat source tree as the ``web_guard`` package for local tests.

    The project keeps its modules directly in ``src`` and maps that directory to
    the ``web_guard`` package in ``pyproject.toml``. An installed package uses
    that mapping automatically. Loading the package this way lets the complete
    test suite run from a checkout without requiring an editable install.
    """

    spec = importlib.util.spec_from_file_location(
        "web_guard",
        _SOURCE_ROOT / "__init__.py",
        submodule_search_locations=[str(_SOURCE_ROOT)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("The Web Guard source package could not be loaded.")
    module = importlib.util.module_from_spec(spec)
    sys.modules["web_guard"] = module
    spec.loader.exec_module(module)


_install_source_package()

sys.path.insert(0, str(Path(__file__).resolve().parent))
_helpers = importlib.import_module("helpers")
_config = importlib.import_module("web_guard.config")
RunningServer = _helpers.RunningServer
make_context = _helpers.make_context
make_response = _helpers.make_response
Settings = _config.Settings


@pytest.fixture
def serve():
    """Start one or more loopback servers and stop them after the test."""

    servers: list[RunningServer] = []

    def _serve(routes, base_headers=None, tls=None) -> RunningServer:
        server = RunningServer(routes, base_headers=base_headers, tls=tls)
        servers.append(server)
        return server.start()

    yield _serve
    for server in reversed(servers):
        server.stop()


@pytest.fixture
def fast_settings() -> Settings:
    """Settings tuned for fast, offline loopback tests."""

    return Settings(delay=0.0, timeout=2.0, probe_tls=False)


@pytest.fixture
def context_factory():
    """Expose the context builder to tests."""

    return make_context


@pytest.fixture
def response_factory():
    """Expose the response builder to tests."""

    return make_response
