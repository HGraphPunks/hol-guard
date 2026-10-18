"""Strict Managed Controls parsing and delivery binding for daemon sync."""

from __future__ import annotations

from ..managed_controls_policy_bundle import (
    parsed_managed_controls_from_validated_policy_bundle,
    signed_cloud_extension_projection_digest,
)
from ..managed_controls_policy_fields import (
    ManagedControlsPolicyError,
    ParsedManagedControlsPolicy,
    _without_extension_fields,
)
from ..policy_bundle_delivery import validated_managed_policy_delivery
from ..runtime.extension_catalog_completion import current_catalog_registry
from ..runtime.extension_catalog_handshake import runtime_summary_device_id
from ..runtime.runner import _managed_controls_negotiated_capabilities
from ..store import GuardStore


def daemon_managed_controls_candidate(
    *,
    store: GuardStore,
    payload: dict[str, object],
    policy_bundle: dict[str, object],
    device_id: str,
) -> tuple[
    ParsedManagedControlsPolicy | None,
    frozenset[str],
    dict[str, object] | None,
    str | None,
]:
    capabilities = _managed_controls_negotiated_capabilities(store, payload)
    runtime_summary = getattr(store, "get_sync_payload", lambda _key: None)("runtime_session_summary")
    document = policy_bundle.get("payload")
    if isinstance(document, dict) and _without_extension_fields(document):
        return None, capabilities, None, None
    try:
        policy = parsed_managed_controls_from_validated_policy_bundle(
            policy_bundle,
            registry=current_catalog_registry(store),
            negotiated_capabilities=capabilities,
            guard_home=store.guard_home,
            runtime_summary=runtime_summary if isinstance(runtime_summary, dict) else None,
        )
    except ManagedControlsPolicyError as error:
        return None, capabilities, None, error.code
    if not policy.has_extension_semantics:
        return None, capabilities, None, None
    delivery_payload = payload.get("policyBundleDelivery")
    delivery_catalog_digest = delivery_payload.get("catalogDigest") if isinstance(delivery_payload, dict) else None
    if policy.cloud_enforcement_digest is not None and delivery_catalog_digest != policy.cloud_enforcement_digest:
        return None, capabilities, None, "policy_enforcement_digest_mismatch"
    projection_digest = (
        signed_cloud_extension_projection_digest(
            policy,
            catalog_digest=delivery_catalog_digest,
        )
        if isinstance(delivery_catalog_digest, str)
        else None
    )
    delivery, error = validated_managed_policy_delivery(
        policy_bundle=policy_bundle,
        delivery_field_provided="policyBundleDelivery" in payload,
        delivery_payload=delivery_payload,
        workspace_id=store.get_cloud_workspace_id(),
        device_id=runtime_summary_device_id(runtime_summary, device_id),
        runtime_summary=runtime_summary,
        expected_extension_projection_digest=projection_digest,
    )
    return policy, capabilities, delivery, error
