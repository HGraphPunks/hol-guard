"""Optional command contracts run against authenticated installed packs.

The core registry remains core-only. Authored metadata grants no activation;
the resident receives a separately prepared pack set and signed policy first.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

COMMAND_MODULES = {
    "test_retired_command_extension_continuity",
    *(
        f"test_guard_command_{name}_extensions"
        for name in ("agentbridge", "blitcp", "digline", "ollama", "tui_runner", "skill_sunset")
    ),
}


@pytest.fixture(scope="session")
def authored_command_catalog():
    from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog
    from scripts.export_extension_directory import native_extensions

    return GeneratedCommandCatalog(native_extensions())


@pytest.fixture(autouse=True)
def optional_command_catalog(request, monkeypatch, tmp_path):
    module = request.module.__name__.rsplit(".", 1)[-1]
    if module not in COMMAND_MODULES | {"test_guard_extension_directory_operations"}:
        return
    catalog = request.getfixturevalue("authored_command_catalog")
    if hasattr(request.module, "BUILT_IN_COMMAND_EXTENSION_REGISTRY"):
        monkeypatch.setattr(request.module, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", catalog)
    if module not in COMMAND_MODULES:
        return

    from codex_plugin_scanner.guard import native_pretool
    from codex_plugin_scanner.guard.catalog_delivery import preparation
    from codex_plugin_scanner.guard.runtime import command_evaluation
    from codex_plugin_scanner.guard.runtime.extension_control_authority import (
        AuthorityHealth,
        ExtensionControlAuthorityView,
    )
    from codex_plugin_scanner.guard.runtime.extension_control_contract import (
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind,
        ControlState,
        ControlTarget,
        ControlTargetKind,
        ExtensionControl,
        ExtensionControlLayer,
    )
    from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
    from tests import command_extension_contracts, mcp_policy_catalog_fixture
    from tests import native_command_test_support as support
    from tests.mcp_policy_native_fixture import _BINDINGS

    delivery = request.getfixturevalue("mcp_policy_delivery")
    monkeypatch.setattr(mcp_policy_catalog_fixture, "_DELIVERY", [delivery])
    original_prepare = preparation.prepare

    def private_prepare(verified, enabled, directory, **kwargs):
        # Preparation creates its parents for normal data IO. The synthetic
        # daemon also writes signed state here, which requires owner-only IO.
        assert directory.is_relative_to(tmp_path)
        assert directory.parent.name == "native-runtime"
        directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.parent.chmod(0o700)
        return original_prepare(verified, enabled, directory, **kwargs)

    monkeypatch.setattr(preparation, "prepare", private_prepare)
    monkeypatch.setattr(command_evaluation, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", catalog)
    monkeypatch.setattr(command_extension_contracts, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", catalog)
    monkeypatch.setattr(support, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", catalog)
    current = [None]
    homes = {}
    monkeypatch.setattr(support, "native_test_guard_home", lambda **kwargs: current[0])

    def close_homes():
        from codex_plugin_scanner.guard.native_resident_client import close_native_residents
        from tests.mcp_policy_native_fixture import _ADMITTED

        for home, _snapshot in homes.values():
            close_native_residents(home)
            _BINDINGS.pop(home, None)
            _ADMITTED.pop(home, None)

    request.addfinalizer(close_homes)

    def review(
        commands, *, cwd=None, home_dir=None, controls=(), managed_controls=(),
        global_lockdown=False, managed_global_lockdown=False, health=AuthorityHealth.PROTECTED,
    ):
        assert not managed_controls and not managed_global_lockdown
        assert health is AuthorityHealth.PROTECTED
        key = (controls, global_lockdown)
        if key not in homes:
            layer = ExtensionControlLayer(
                schema_version=CONTROL_SCHEMA_VERSION,
                kind=ControlLayerKind.LOCAL_ADMIN,
                catalog_digest=catalog.catalog_digest,
                global_lockdown=global_lockdown,
                controls=tuple(
                    ExtensionControl(
                        target=ControlTarget(ControlTargetKind(kind), identity), state=ControlState(state),
                    )
                    for kind, identity, state in controls
                ),
            )
            store = SimpleNamespace(guard_home=tmp_path / f"policy-{len(homes)}")
            mcp_policy_catalog_fixture.admit_mcp_layers(store, (layer,))
            binding = _BINDINGS[store.guard_home]
            snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
                ExtensionControlAuthorityView(
                    health=health,
                    revision=binding["revision"],
                    catalog_digest=binding["catalog_digest"],
                    layers=(replace(layer, catalog_digest=binding["catalog_digest"]),),
                    managed_revision=binding["managed_revision"],
                )
            )
            assert snapshot.effective_digest == binding["effective_digest"]
            homes[key] = (store.guard_home, snapshot)
        guard_home, snapshot = homes[key]
        current[0] = guard_home
        rows = []
        for command in commands:
            payload = native_pretool.review_pre_tool_native(
                command, guard_home=guard_home, cwd=cwd, home_dir=home_dir,
                execution_environment=support._native_test_execution_environment(home_dir) if home_dir else None,
                timeout_seconds=10,
            )
            assert payload is not None, "authenticated optional command resident unavailable"
            admitted = _BINDINGS[guard_home]
            evidence_binding = payload["command_extensions"]["binding"]
            for field in ("program_digest", "catalog_digest", "trust_digest", "effective_digest"):
                assert evidence_binding[field] == admitted[field], field
            rows.append(support.RealNativeReviewFixture(command, payload, snapshot))
        return tuple(rows)

    monkeypatch.setattr(support, "real_native_review_fixtures", review)
