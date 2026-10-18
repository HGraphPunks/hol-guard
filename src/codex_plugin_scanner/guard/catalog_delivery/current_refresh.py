"""Timer/transport/protected-store IO for native current-publication selection.

No hook calls this adapter. Metadata staging and ancestry HTTP finish before
the brief protected-cursor CAS lease. Failed preparation retains the old view.
"""

from __future__ import annotations

import time

from ..native_command_control_authority_store import _key
from . import active_security, current_cache, lifecycle, lifecycle_store, transport
from .authority import VerifiedDistribution
from .discovery import prepare_discovery

PREFIX = "guard-command-discovery-current"
STAMP = "guard-command-discovery-current-enrolled"
COMPLETE = "guard-command-discovery-complete"
ENROLLED = "guard.discovery-current-enrolled.v1"


def _read(store):
    backend = store._policy_integrity_secret_store
    if backend is None or store._should_skip_policy_integrity_keychain_access(backend):
        raise ValueError("discovery_current_protected_store_unavailable")
    value = store._get_policy_integrity_secret_from_store(store._build_scoped_secret_ref(PREFIX))
    stamp = store._get_policy_integrity_secret_from_store(store._build_scoped_secret_ref(STAMP))
    if value is None and stamp is not None:
        raise ValueError("discovery_current_protected_cursor_missing")
    if value is not None and stamp != ENROLLED:
        raise ValueError("discovery_current_protected_stamp_missing")
    return value


def _capture(store):
    return lifecycle_store.read(store), _read(store), active_security.read(store)


def _invoke(store, captured, **fields):
    floor, cursor, security = captured
    return lifecycle.invoke(
        "discovery-current", key=_key(store).hex(), floor=floor, cursor=cursor, security=security, **fields
    )


def refresh(store):
    """Fixed verified factory -> native monotonic cursor -> complete handle."""
    captured = _capture(store)
    _invoke(store, captured)
    directory = store.guard_home / "command-packs" / "current-publication"
    provenance = []
    # A transport/verifier failure may restore only the protected completed
    # view. Cache files cannot nominate a newer Root through this update path.
    authority = transport.fetch_root(now=int(time.time()), verified_io=lambda root, data: provenance.append(data))
    if type(authority) is not VerifiedDistribution:
        raise ValueError("discovery_current_authenticated_publication_required")
    # Security observation is sparse and independent of full browsing traversal.
    # Known negative facts are committed/quarantined before staging metadata.
    active_security.observe_preparation(store, authority)
    captured = _capture(store)
    fields = dict(publication=authority.data.decode(), now=time.time())
    while True:
        result = _invoke(store, captured, **fields)
        if "lineage_kind" not in result:
            break
        floor = lifecycle.invoke("read", key=_key(store).hex(), floor=result["lineage_floor"])
        fields[result["lineage_kind"] + "_ancestry"] = lifecycle.ancestry(floor, result["lineage_source"])
    # Retain the authenticated observation even when metadata is incomplete.
    # This cursor is independent of active policy and approval identities.
    # Write/fsync the bounded factory bytes before the lease; only rename the
    # prepared files during the protected cursor commit.
    with (
        current_cache.stage(directory, authority, provenance[0] if provenance else None) as pending,
        store._extension_control_authority_lock(),
    ):
        if _capture(store) != captured:
            raise ValueError("discovery_current_observation_conflict")
        result = _invoke(store, captured, **{**fields, "now": time.time()})
        if "record" not in result:
            raise ValueError("discovery_current_observation_conflict")
        backend = store._policy_integrity_secret_store
        backend.set_secret(store._build_scoped_secret_ref(STAMP), ENROLLED)
        if store._get_policy_integrity_secret_from_store(store._build_scoped_secret_ref(STAMP)) != ENROLLED:
            raise ValueError("discovery_current_protected_write_mismatch")
        backend.set_secret(store._build_scoped_secret_ref(PREFIX), result["record"])
        if _read(store) != result["record"]:
            raise ValueError("discovery_current_protected_write_mismatch")
        current_cache.publish(pending)
        _prune(store, directory)
    handle = prepare_discovery(
        store.guard_home,
        authority,
        fetch=transport.cached_fetcher(store.guard_home / "command-packs" / "transfers"),
    )
    # A security update or activation racing preparation cannot publish a view
    # below its new floors. No network is performed during this final check.
    with store._extension_control_authority_lock():
        final = _invoke(store, _capture(store), **{**fields, "now": time.time()})
        if "record" not in final:
            raise ValueError("discovery_current_observation_conflict")
        backend.set_secret(store._build_scoped_secret_ref(COMPLETE), final["record"])
        if store._get_policy_integrity_secret_from_store(store._build_scoped_secret_ref(COMPLETE)) != final["record"]:
            raise ValueError("discovery_current_protected_write_mismatch")
        _prune(store, directory)
    return handle


def _prune(store, directory):
    complete = store._get_policy_integrity_secret_from_store(store._build_scoped_secret_ref(COMPLETE))
    plan = _invoke(store, _capture(store), complete=complete, files=current_cache.filenames(directory))
    current_cache.remove(directory, plan["remove"])


def restore(store):
    """Reverify cached last-complete bytes; Rust authorizes browsing retention."""
    captured = _capture(store)
    complete = store._get_policy_integrity_secret_from_store(store._build_scoped_secret_ref(COMPLETE))
    retained = _invoke(store, (captured[0], complete, captured[2]))["retained"]
    directory = store.guard_home / "command-packs" / "current-publication"
    authority = current_cache.load(directory, retained, now=int(time.time()))
    _invoke(store, captured, publication=authority.data.decode(), now=time.time(), restore=True, complete=complete)
    handle = prepare_discovery(
        store.guard_home, authority, fetch=transport.cached_fetcher(store.guard_home / "command-packs" / "transfers")
    )
    _invoke(
        store, _capture(store), publication=authority.data.decode(), now=time.time(), restore=True, complete=complete
    )
    return handle
