"""Existing protected secret-store IO; Rust authenticates and advances records."""

from __future__ import annotations

from ..native_command_control_authority_io import require_exclusive_command_control_mutation_lease
from ..native_command_control_authority_store import _key
from . import lifecycle

PREFIX = "guard-command-pack-lifecycle"
STAMP = "guard-command-pack-lifecycle-enrolled"


def _stamp(store):
    return store._get_policy_integrity_secret_from_store(store._build_scoped_secret_ref(STAMP))


def _mark(store, stamp):
    backend = store._policy_integrity_secret_store
    backend.set_secret(store._build_scoped_secret_ref(STAMP), stamp)
    if _stamp(store) != stamp:
        raise ValueError("pack_lifecycle_protected_write_mismatch")


def read(store):
    backend = store._policy_integrity_secret_store
    if backend is None or store._should_skip_policy_integrity_keychain_access(backend):
        raise ValueError("pack_lifecycle_protected_store_unavailable")
    return store._get_policy_integrity_secret_from_store(store._build_scoped_secret_ref(PREFIX))


def inspect(store):
    record = read(store)
    return record, lifecycle.invoke("read", key=_key(store).hex(), floor=record)


def write(store, record):
    require_exclusive_command_control_mutation_lease(store.guard_home)
    lifecycle.invoke("read", key=_key(store).hex(), floor=record)
    backend = store._policy_integrity_secret_store
    if backend is None or store._should_skip_policy_integrity_keychain_access(backend):
        raise ValueError("pack_lifecycle_protected_store_unavailable")
    backend.set_secret(store._build_scoped_secret_ref(PREFIX), record)
    if read(store) != record:
        raise ValueError("pack_lifecycle_protected_write_mismatch")


def enroll_installed(store, authority):
    """Installation enrollment only; never invoked by activation/recovery.

    A missing record in any later API activation is an explicit failure. This
    helper does not recover a lost floor and cannot overwrite a retained one.
    """
    require_exclusive_command_control_mutation_lease(store.guard_home)
    if read(store) is not None or _stamp(store) is not None:
        raise ValueError("pack_lifecycle_already_enrolled")
    result = lifecycle.invoke("enroll", key=_key(store).hex(), **lifecycle.release_evidence(authority))
    _mark(store, result["stamp"])
    write(store, result["record"])


def migrate_installed(store, authority):
    """Startup/installation only, under EX; never a preview repair path.

    Stamp first: an interrupted protected write fails closed on next startup.
    Older native-phase floors may predate the stamp; authenticate and retain
    them exactly. Missing/corrupt stamped floors are never reconstructed.
    """
    require_exclusive_command_control_mutation_lease(store.guard_home)
    import json

    key = store._authority_key(required=False)
    anchor = store._secret_store().get_secret(store._anchor_ref())
    with store._connect() as connection:
        row = connection.execute("select * from extension_control_authority_snapshot where singleton=1").fetchone()
    from .activation_store import header_for_store

    result = lifecycle.invoke(
        "migrate",
        key=_key(store).hex(),
        floor=read(store),
        stamp=_stamp(store),
        legacy_key=None if key is None else key.hex(),
        legacy_anchor=None if anchor is None else json.loads(anchor),
        legacy_snapshot=None
        if row is None
        else dict(record=row["snapshot_json"], digest=row["snapshot_digest"], mac=row["snapshot_mac"]),
        legacy_activation=header_for_store(store, _key(store)),
        **lifecycle.release_evidence(authority),
    )
    if result["record"] is not None:
        _mark(store, result["stamp"])
        write(store, result["record"])


def migration_retained(store):
    """Authenticate a no-op startup under SH without creating keys or secrets."""
    floor = read(store)
    if floor is None:
        return False
    stamp = _stamp(store)
    result = lifecycle.invoke("migrate", key=_key(store, create=False).hex(), floor=floor, stamp=stamp)
    return result == {"record": floor, "stamp": stamp}


def check(store, captured, next_record):
    require_exclusive_command_control_mutation_lease(store.guard_home)
    observed, _ = inspect(store)
    if observed != captured and observed != next_record:
        raise ValueError("pack_lifecycle_prepared_floor_conflict")


def commit(store, captured, next_record):
    check(store, captured, next_record)
    write(store, next_record)
