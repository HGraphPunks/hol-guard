"""The installed MCP fixture validates metadata with its packaged executable."""

from __future__ import annotations

import os

import pytest

from codex_plugin_scanner.guard.catalog_delivery import installed_bundle
from codex_plugin_scanner.guard.extension_builder import native_source_compiler as transport

from .test_native_pack_preparation import BINARY
from .test_native_pack_preparation import delivery as _delivery
from .test_native_pack_upgrade import release as _release


def test_installed_mcp_fixture_clears_checkout_overrides_for_real_metadata_validation(tmp_path, monkeypatch):
    overrides = ("HOL_GUARD_NATIVE_SOURCE_COMPILER", "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER")
    for name in overrides:
        monkeypatch.delenv(name, raising=False)
    expected, _install = _release.__wrapped__(tmp_path, monkeypatch)
    package = installed_bundle._package()
    inventory = dict(
        native=package / "_native",
        program=transport._PACKAGED_PROGRAM,
        package=package,
        published=tmp_path / "published",
        engine=expected.engine,
    )
    for name in overrides:
        monkeypatch.setenv(name, str(BINARY))
    with pytest.raises(ValueError, match="compiler override is not permitted alongside a packaged compiler"):
        installed_bundle.load_installed_bundle()
    verified, _cache, engine = _delivery.__wrapped__(inventory, tmp_path, monkeypatch)
    assert all(name not in os.environ for name in overrides)
    assert verified.data == expected.data
    assert engine == verified.engine == expected.engine
