"""Strict negotiated v2 transfer; only verified completion reports success."""

from __future__ import annotations

import urllib.parse
from collections.abc import Callable

from .extension_catalog_pages import CAPABILITY, LIMITS, UPLOAD_PATH, PreparedCatalogView


def upload_url(runtime_sync_url: str, upload_path: object) -> str:
    parsed = urllib.parse.urlsplit(runtime_sync_url)
    # Preserve the configured origin/query, never trust a negotiated host or URL.
    if (
        upload_path != UPLOAD_PATH
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.path != "/api/guard/runtime/sessions/sync"
    ):
        raise RuntimeError("Invalid Extension catalog sync origin/path")
    try:
        _ = parsed.port
    except ValueError as error:
        raise RuntimeError("Invalid Extension catalog sync origin/path") from error
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, UPLOAD_PATH, parsed.query, ""))


def validate_response(value: object, *, expected_digest: str, completing: bool) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"schemaVersion", "catalogDigest", "accepted", "complete"}
        or value.get("schemaVersion") != "guard.extension-catalog-sync.v2"
        or value.get("catalogDigest") != expected_digest
        or value.get("accepted") is not True
        or type(value.get("complete")) is not bool
        or (completing and value.get("complete") is not True)
    ):
        raise RuntimeError("Invalid Extension catalog v2 sync response")


def _sync_catalog_view(
    *,
    runtime_sync_url: str,
    runtime_response: dict[str, object],
    session_payload: dict[str, object],
    view: PreparedCatalogView,
    send: Callable[[str, bytes], object],
) -> dict[str, object]:
    """Send one immutable observed view with replay-stable bounded requests.

    Transport may retry identical request bytes. No complete is sent after a
    page/transport/verification failure. Each fresh attempt starts at begin;
    receiver idempotency handles lost acknowledgements and concurrent attempts.
    """
    manifest = view.manifest
    expected = manifest["catalogDigest"]
    capabilities = session_payload.get("managedControlsCapabilities")
    if (
        not isinstance(capabilities, list)
        or CAPABILITY not in capabilities
        or session_payload.get("extensionCatalogViewDigest") != expected
        or session_payload.get("extensionCatalogEnforcementDigest") != manifest["enforcementCatalogDigest"]
        or session_payload.get("extensionCatalogGeneratedAt") != manifest["generatedAt"]
    ):
        raise RuntimeError("Extension catalog v2 view differs from observed posture")
    signal = runtime_response.get("extensionCatalogSync")
    if (
        not isinstance(signal, dict)
        or set(signal) != {"protocolVersion", "catalogDigest", "catalogKnown", "uploadRequired", "uploadPath", "limits"}
        or signal.get("protocolVersion") != CAPABILITY
        or signal.get("catalogDigest") != expected
        or type(signal.get("catalogKnown")) is not bool
        or type(signal.get("uploadRequired")) is not bool
        or signal["catalogKnown"] is signal["uploadRequired"]
        or not isinstance(signal.get("limits"), dict)
        or set(signal["limits"]) != set(LIMITS)
        or any(
            type(signal["limits"][key]) is not int or signal["limits"][key] != limit for key, limit in LIMITS.items()
        )
    ):
        raise RuntimeError("Invalid Extension catalog v2 handshake response")
    url = upload_url(runtime_sync_url, signal["uploadPath"])
    if signal["catalogKnown"]:
        return {"extension_catalog_sync_status": "already_known", "extension_catalog_sync_digest": expected}

    # Manifest binds enforcement identity and observation time independently of
    # content-only discovery identity. A new observation cannot reuse an old key.
    def request(operation: str, ordinal: int | None = None) -> None:
        body = view.request_bytes(operation, ordinal)
        if len(body) > LIMITS["maxPageBytes"] + 1024:
            raise RuntimeError("Extension catalog v2 request budget exceeded")
        validate_response(send(url, body), expected_digest=expected, completing=operation == "complete")

    request("begin")
    for ordinal in range(manifest["pageCount"]):
        request("page", ordinal)
    request("complete")
    return {"extension_catalog_sync_status": "uploaded", "extension_catalog_sync_digest": expected}


def sync_catalog_view(*, view: PreparedCatalogView, **kwargs) -> dict[str, object]:
    with view.pinned():
        return _sync_catalog_view(view=view, **kwargs)
