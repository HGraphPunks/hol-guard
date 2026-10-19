"""Bounded native Cloud producer bridge; no Python catalog construction."""

from __future__ import annotations

import base64
import hashlib
import json
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CAPABILITY = "extension-catalog.v2"
UPLOAD_PATH = "/api/guard/runtime/extension-catalog/sync-v2"
LIMITS = {
    "maxPageEntries": 64,
    "maxPageBytes": 2 * 1024 * 1024,
    "maxEntryBytes": 1_000_000,
    "maxPages": 8192,
    "maxTotalBytes": 512 * 1024 * 1024,
}


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def native_call(home: Path, **request: object) -> dict[str, Any]:
    from ..native_execution import _resident_request
    from .extension_catalog_sync import ExtensionCatalogLimitError

    reply = _resident_request(
        operation="cloud_catalog",
        request={"guard_home": str(home.absolute()), **request},
        guard_home=home,
        timeout_seconds=120.0,
        required_feature="cloud-catalog-producer-v2",
        response_schema="guard-cloud-catalog-result.v2",
        max_request_bytes=4 * 1024 * 1024,
    )
    if not isinstance(reply, dict):
        raise RuntimeError("Native complete catalog producer unavailable")
    if reply.get("error") == "catalog_limit":
        raise ExtensionCatalogLimitError("Complete catalog exceeds native wire limits")
    payload = reply.get("payload")
    if not isinstance(payload, dict) or "error" in reply:
        raise ValueError("Native complete catalog producer rejected metadata")
    if "policy_error" in payload:
        from ..managed_controls_policy_fields import ManagedControlsPolicyError

        raise ManagedControlsPolicyError(payload["policy_error"], payload["message"])
    return payload


@dataclass(frozen=True)
class PreparedCatalogView:
    guard_home: Path
    token: str
    _manifest: bytes
    discovery_root: str
    discovery_authority: str

    @classmethod
    def from_native(cls, home: Path, payload: dict[str, Any]) -> PreparedCatalogView:
        return cls(
            home,
            payload["token"],
            encoded(payload["manifest"]),
            payload["discovery_root"],
            payload["discovery_authority"],
        )

    @property
    def manifest(self) -> dict[str, Any]:
        return json.loads(self._manifest)

    def request_bytes(self, operation: str, ordinal: int | None = None) -> bytes:
        body = bytearray()
        total = expected = None
        while total is None or len(body) < total:
            result = native_call(
                self.guard_home,
                action="request",
                token=self.token,
                operation=operation,
                ordinal=ordinal,
                offset=len(body),
            )
            size = result.get("total_bytes")
            if (
                type(size) is not int
                or not 0 < size <= LIMITS["maxPageBytes"] + 1024
                or result.get("offset") != len(body)
            ):
                raise ValueError("Native catalog request exceeds transport budget")
            if total is None:
                total, expected = size, result.get("body_sha256")
            if size != total or result.get("body_sha256") != expected:
                raise ValueError("Native catalog request changed between chunks")
            chunk = base64.b64decode(result["body_chunk"], validate=True)
            if not chunk or len(chunk) > 512 * 1024 or len(body) + len(chunk) > total:
                raise ValueError("Native catalog chunk exceeds transport budget")
            body.extend(chunk)
        if hashlib.sha256(body).hexdigest() != expected:
            raise ValueError("Native catalog request checksum differs")
        return bytes(body)

    def pages(self):
        for ordinal in range(self.manifest["pageCount"]):
            yield json.loads(self.request_bytes("page", ordinal))["page"]

    def legacy(self):
        with self.pinned():
            return native_call(self.guard_home, action="legacy", token=self.token)["catalog"]

    @contextmanager
    def pinned(self):
        lease = native_call(self.guard_home, action="acquire", token=self.token)["lease"]
        try:
            yield
        finally:
            native_call(self.guard_home, action="release", lease=lease)
