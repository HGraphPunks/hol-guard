"""Local session/discovery adapters for native Cloud policy proofs.

No metadata, enforcement digest or filesystem location from a policy response
is accepted here. Missing authenticated observation identity fails closed.
"""

from __future__ import annotations

import importlib
from datetime import datetime, timezone
from pathlib import Path

from ..managed_controls_policy_fields import ManagedControlsPolicyError
from .extension_catalog_provider import observed_view


def local_policy_view(*, guard_home: Path, runtime_summary: dict[str, object], registry) -> dict[str, object]:
    """Marshal a previously authenticated session and current local discovery.

    The session adapter must retain the full authenticated observation identity;
    a response's selected metadata is never a substitute for that local binding.
    """
    identity = runtime_summary.get("policyMetadataIdentity")
    if not isinstance(identity, dict) or set(identity) != {"ownerUserId", "workspaceId", "deviceId", "runtimeId"}:
        raise ManagedControlsPolicyError(
            "policy_observation_identity_missing", "Authenticated policy observation identity is unavailable."
        )
    if identity.get("runtimeId") != runtime_summary.get("runtime_credential_id") or identity.get(
        "deviceId"
    ) != runtime_summary.get("runtime_device_id"):
        raise ManagedControlsPolicyError(
            "policy_observation_identity_mismatch", "Policy observation session identity changed."
        )
    observed_at = runtime_summary.get("policyMetadataObservedAt")
    if not isinstance(observed_at, str) or not observed_at:
        raise ManagedControlsPolicyError(
            "policy_completed_observation_missing", "Authenticated completed observation time is unavailable."
        )
    view = observed_view(runtime_summary, guard_home)
    discovery = importlib.import_module("..catalog_delivery.discovery", __package__)
    handle = discovery.require_handle(discovery.installed_discovery(guard_home), guard_home)
    if (view.discovery_root, view.discovery_authority) != (handle.root, handle.authority):
        raise ManagedControlsPolicyError("policy_local_view_invalid", "Policy discovery observation changed.")
    manifest = view.manifest
    if manifest["enforcementCatalogDigest"] != registry.catalog_digest:
        raise ManagedControlsPolicyError("policy_enforcement_digest_mismatch", "Policy enforcement state changed.")
    from .extension_catalog_completion import local_observation
    from .extension_catalog_pages import native_call

    native_call(
        guard_home,
        action="completion_read",
        token=view.token,
        observation=local_observation(view, registry),
        identity=identity,
        observed_at=observed_at,
    )
    return {
        "guard_home": str(guard_home.absolute()),
        "token": view.token,
        "view_digest": manifest["catalogDigest"],
        "identity": dict(identity),
        "observed_at": observed_at,
        "now": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "observation": {
            "guard_home": str(guard_home.absolute()),
            "discovery_root": handle.root,
            "discovery_authority": handle.authority,
            "enforcement_catalog_digest": registry.catalog_digest,
            "guard_version": manifest["guardVersion"],
            "generated_at": manifest["generatedAt"],
        },
    }


def policy_view_ready(*, store, registry) -> bool:
    """Require the compatible native proof path against an authenticated view.

    Authority health and atomic application prerequisites are checked by the
    caller. The production parser must return an actual v2 proof, so an older
    resident cannot gain capabilities by ignoring new request fields.
    """
    from ..managed_controls_policy_fields import parse_managed_controls_policy_fields

    summary = getattr(store, "get_sync_payload", lambda _key: None)("runtime_session_summary")
    if not isinstance(summary, dict):
        return False
    try:
        view = local_policy_view(guard_home=store.guard_home, runtime_summary=summary, registry=registry)
        parsed = parse_managed_controls_policy_fields(
            {
                "x-hol-extension-controls": {
                    "schemaVersion": "guard.extension-controls.v1",
                    "authorityMode": "managed-restrictive",
                    "controls": [],
                },
                "spec": {"rules": []},
            },
            registry=registry,
            guard_home=store.guard_home,
            cloud_view=view,
            negotiated_capabilities=frozenset(
                {"extension-control-layer.v1", "policy-extension-targets.v1", "managed-controls-atomic-apply.v1"}
            ),
        )
        return parsed.cloud_projection_digest is not None
    except (ImportError, OSError, RuntimeError, TypeError, ValueError):
        return False
