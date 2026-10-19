"""Verified factory boundary and thin IO for Rust metadata preparation.

Rust requests bounded fetches and owns every traversal, proof, index, CAS write
and handle check. This module never interprets catalog or transport metadata.
"""

from __future__ import annotations

import base64
import json
import threading
from contextlib import suppress
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..file_identity import full_stat_identity
from ..native_resident_client import native_resident_client_request
from ..native_runtime import _isolated_environment, native_runtime_status
from ..strict_json_pairs import unique_json_object
from .authority import VerifiedDistribution

CAPABILITY = "catalog-prepare-v1"
BATCH_CAPABILITY = "catalog-prepare-batch-v1"
_lock = threading.Lock()
_cached: tuple[Path, str, DiscoveryHandle] | None = None
_transport: ContextVar[list[Any] | None] = ContextVar("catalog_preparation_transport", default=None)


@dataclass(frozen=True, slots=True, init=False)
class DiscoveryHandle:
    guard_home: Path
    native: dict[str, Any]

    def __new__(cls):
        raise TypeError("discovery handles must be prepared from authenticated metadata")

    @property
    def root(self):
        return self.native["root"]

    @property
    def authority(self):
        return self.native["authority"]

    @property
    def expires_at(self):
        return self.native["expires_at"]


def _installed_type():
    from .installed_bundle import VerifiedInstalledBundle

    return VerifiedInstalledBundle


def _native(guard_home, action):
    captured = _transport.get()
    status = captured[0] if captured else native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or CAPABILITY not in status.capabilities.features
    ):
        raise ValueError("native discovery preparation unavailable")
    metadata = status.identity.path.lstat()
    stamp = full_stat_identity(metadata)
    if metadata.st_size != status.identity.size or metadata.st_mtime_ns != status.identity.mtime_ns:
        raise ValueError("native discovery runtime changed")
    if captured is not None:
        if not captured:
            captured.extend((status, stamp))
        elif stamp != captured[1]:
            raise ValueError("native discovery runtime changed")
    if action["kind"] == "begin":
        if BATCH_CAPABILITY not in status.capabilities.features:
            raise ValueError("native discovery batched preparation unavailable")
        action = {**action, "kind": "begin_batched"}
    payload = json.dumps(
        {
            "operation": "catalog_prepare_v1",
            "request": {"guard_home": str(guard_home), "action": action},
            "deadline_budget_ms": 60_000,
        },
        separators=(",", ":"),
    ).encode()
    response = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=payload,
        timeout_seconds=60,
    )
    if response is None:
        raise ValueError("native discovery transport unavailable")
    value = json.loads(response, object_pairs_hook=unique_json_object)
    if not isinstance(value, dict) or value.get("schema") != "guard.catalog-prepare-result.v1":
        raise ValueError("native discovery result invalid")
    if value.get("outcome") == "error":
        raise ValueError(value.get("error_code", "native discovery failed"))
    return value


def prepare_discovery(guard_home: Path, authority, *, fetch=None) -> DiscoveryHandle:
    """Forward verified factory bytes; preparation runs outside hook decisions."""
    token = _transport.set([])
    try:
        return _prepare_discovery(guard_home, authority, fetch=fetch)
    finally:
        _transport.reset(token)


def _recheck_runtime():
    captured = _transport.get()
    if captured:
        current = native_runtime_status()
        if not current.available or not current.compatible or current.identity != captured[0].identity:
            raise ValueError("native discovery runtime changed")


def _prepare_discovery(guard_home: Path, authority, *, fetch=None) -> DiscoveryHandle:
    global _cached
    if type(authority) is VerifiedDistribution:
        profile = "remote"
        expiry = authority.expires_at
        if fetch is None:
            raise ValueError("discovery remote transport absent")
    elif type(authority) is _installed_type():
        profile, expiry, fetch = "installed", None, authority.preparation_fetch()
    else:
        raise ValueError("discovery requires factory-authenticated authority")
    guard_home = guard_home.absolute()
    with _lock:
        if _cached is not None and _cached[:2] == (guard_home, authority.digest):
            try:
                handle = require_handle(_cached[2], guard_home)
                _recheck_runtime()
                return handle
            except ValueError as error:
                if str(error) not in {
                    "catalog_prepare_handle_invalid",
                    "catalog_prepare_object_corrupt",
                    "catalog_prepare_object_unavailable",
                }:
                    raise
                # A restarted resident has no registered handle. Re-prepare
                # from the same verified factory; Rust rechecks every proof.
                _cached = None
        result = _native(
            guard_home,
            {
                "kind": "begin",
                "authority": {
                    "data": base64.b64encode(authority.data).decode("ascii"),
                    "digest": authority.digest,
                    "source_sha": authority.source_sha,
                    "profile": profile,
                    "expires_at": expiry,
                },
            },
        )
        session = None
        try:
            while result.get("outcome") in {"fetch", "fetch_batch", "continue"}:
                session = result["session"]
                if result["outcome"] == "continue":
                    result = _native(guard_home, {"kind": "resume", "session": session})
                    continue
                if result["outcome"] == "fetch_batch":
                    requests = result["fetches"]
                    if not isinstance(requests, list) or not 0 < len(requests) <= 64:
                        raise ValueError("native discovery batch invalid")
                    data = [base64.b64encode(fetch(r["location"], r["length"])).decode("ascii") for r in requests]
                    result = _native(guard_home, {"kind": "advance_batch", "session": session, "data": data})
                    continue
                request = result["fetch"]
                data = fetch(request["location"], request["length"])
                result = _native(
                    guard_home,
                    {"kind": "advance", "session": session, "data": base64.b64encode(data).decode("ascii")},
                )
            if result.get("outcome") != "complete":
                raise ValueError("native discovery preparation incomplete")
        except BaseException:
            if session is not None:
                with suppress(ValueError, OSError):
                    _native(guard_home, {"kind": "abort", "session": session})
            raise
        _recheck_runtime()
        handle = object.__new__(DiscoveryHandle)
        object.__setattr__(handle, "guard_home", guard_home)
        object.__setattr__(handle, "native", result["handle"])
        _cached = (guard_home, authority.digest, handle)
        return handle


def installed_discovery(guard_home: Path) -> DiscoveryHandle:
    """Nonblocking control-plane readiness; the worker verifies and prepares."""
    from .discovery_ready import installed_ready

    return installed_ready(guard_home)


def require_handle(handle, guard_home: Path) -> DiscoveryHandle:
    if type(handle) is not DiscoveryHandle:
        raise ValueError("discovery handle is unverified")
    result = _native(guard_home.absolute(), {"kind": "validate", "handle": handle.native})
    if result.get("outcome") != "valid":
        raise ValueError("native discovery handle invalid")
    return handle
