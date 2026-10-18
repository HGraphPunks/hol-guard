"""Factory capability and active-metadata marshaling for the native producer."""

from __future__ import annotations

import importlib
from contextlib import suppress
from pathlib import Path

from .extension_catalog_pages import PreparedCatalogView, native_call


def _raw_extension(item):
    """Marshal local objects without computing a Cloud projection in Python."""
    return {
        "extension_id": item.extension_id,
        "version": item.version,
        "name": item.name,
        "source": item.source,
        "executables": item.executables,
        "ecosystem_ids": item.ecosystem_ids,
        "risk_classes": item.risk_classes,
        "delegated_protection": item.delegated_protection,
        "permissions": [
            {
                "extension_id": item.extension_id,
                "permission_id": p.permission_id,
                "label": p.label,
                "configurable": p.configurable,
                "risk_tier": p.risk_tier,
                "typed_capabilities": p.typed_capabilities,
            }
            for p in item.permissions
        ],
    }


def prepare_installed_catalog_view(
    guard_home: Path, *, registry, guard_version: str, generated_at: str
) -> PreparedCatalogView:
    discovery = importlib.import_module("..catalog_delivery.discovery", __package__)
    handle = discovery.require_handle(discovery.installed_discovery(guard_home), guard_home)
    # A root is metadata integrity only. Factory authentication remains required.
    observation = {
        "guard_home": str(guard_home.absolute()),
        "discovery_root": handle.root,
        "discovery_authority": handle.authority,
        "enforcement_catalog_digest": registry.catalog_digest,
        "guard_version": guard_version,
        "generated_at": generated_at,
    }
    draft = native_call(guard_home, action="begin", observation=observation)["draft"]
    try:
        for item in registry.extensions:
            native_call(guard_home, action="append", draft=draft, entry=_raw_extension(item))
        discovery.require_handle(handle, guard_home)
        result = native_call(guard_home, action="finish", draft=draft)
        discovery.require_handle(handle, guard_home)
        return PreparedCatalogView.from_native(guard_home, result)
    except BaseException:
        with suppress(ValueError, RuntimeError, OSError):
            native_call(guard_home, action="abort", draft=draft)
        raise


def remember_view(view: PreparedCatalogView) -> PreparedCatalogView:
    # Exact-content timestamp pinning and bounded eviction are native-owned.
    return view


def observed_view(session: dict[str, object], guard_home: Path | None = None) -> PreparedCatalogView:
    if guard_home is None:
        raise ValueError("Explicit Guard home required for native catalog observation")
    result = native_call(
        guard_home,
        action="observe",
        view_digest=session.get("extensionCatalogViewDigest"),
        enforcement_digest=session.get("extensionCatalogEnforcementDigest"),
        generated_at=session.get("extensionCatalogGeneratedAt"),
    )
    return PreparedCatalogView.from_native(guard_home, result)
