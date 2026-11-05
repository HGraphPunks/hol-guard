"""Freeze transactional World outcomes from the unchanged Python source.

This is fixture production, never benchmark runtime. The public synthetic seed
is solely a test vector; live controllers must receive a separately pinned key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.world import COLLECTIONS, World

ROOT = Path(__file__).resolve().parents[3]
DEST = ROOT / "ci/gauntlet-rs/crates/gauntlet-world/tests/python_world_20261027.json"
SEED = bytes(range(32))


def digest(value):
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def seed():
    records = []
    for family, collections in sorted(COLLECTIONS.items()):
        collection = sorted(collections)[0]
        for number in range(3):
            records.append(
                {
                    "id": f"{family}-{number}",
                    "collection": collection,
                    "tenant_id": "task-tenant",
                    "owner_id": "bench-user",
                    "version": 1,
                    "acl": {"read": ["bench-user"], "write": ["bench-user"]},
                    "data": {
                        "zeta": "Alpha Straße 😀",
                        "alpha": number,
                        "nested": {"last": 2, "first": 1},
                        "float": 1e-7,
                        "attachments": [{"id": "attachment", "body": "fixture"}],
                    },
                }
            )
    private = {**records[0], "id": "acl-denied", "acl": {"read": ["someone"], "write": ["someone"]}}
    public = {**records[0], "id": "public-read", "acl": {"read": ["*"], "write": ["someone"]}}
    return {
        "schema": "gauntlet-workflow-snapshot.v1",
        "workflow_id": "rust-world-parity",
        "actor_id": "bench-user",
        "provider_scope": {"tenants": ["task-tenant", "other-tenant"]},
        "records": [*records, private, public],
    }


def main():
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    initial = seed()
    cases = []
    with tempfile.TemporaryDirectory(prefix="gauntlet-world-parity-") as tmp:
        world = World.create(Path(tmp) / "world.db", initial, signing_key=key)

        def call(operation, args):
            request_id = f"request-{len(cases) + 1}"
            row = {"operation": operation, "arguments_json": json.dumps(args), "request_id": request_id}
            try:
                result = world.call(operation, args, request_id)
                row["result"] = result
            except (ValueError, PermissionError) as error:
                row["error"] = {"category": type(error).__name__, "message": str(error)}
                result = None
            receipts = world.receipts()
            row.update(
                snapshot_digest=digest(world.snapshot()), receipts_digest=digest(receipts), receipt_count=len(receipts)
            )
            cases.append(row)
            return result

        for family, collections in sorted(COLLECTIONS.items()):
            collection = sorted(collections)[0]
            call(f"{family}.read", {"record_id": f"{family}-0", "fields": ["alpha", "missing"]})
            first = call(f"{family}.search", {"collection": collection, "limit": 1})
            call(
                f"{family}.search",
                {"collection": collection, "limit": 1, "cursor": first["next_cursor"], "fields": ["zeta"]},
            )
            call(f"{family}.search", {"collection": collection, "query": '"zeta": "Alpha'})
            call(f"{family}.search", {"collection": collection, "query": '"last": 2, "first": 1'})
            call(f"{family}.search", {"collection": collection, "query": "STRASSE"})
            call(f"{family}.search", {"collection": collection, "query": r"\u00df"})
            call(f"{family}.search", {"collection": collection, "limit": True})
            call(
                f"{family}.create",
                {
                    "collection": collection,
                    "record_id": f"new-{family}",
                    "data": {"z": 1, "a": 2},
                    "idempotency_key": f"create-{family}",
                },
            )
            call(
                f"{family}.create",
                {
                    "collection": collection,
                    "record_id": f"new-{family}",
                    "data": {"z": 1, "a": 2},
                    "idempotency_key": f"create-{family}",
                },
            )
            call(
                f"{family}.create",
                {
                    "collection": collection,
                    "record_id": f"other-{family}",
                    "data": {},
                    "idempotency_key": f"create-{family}",
                },
            )
            call(
                f"{family}.update", {"record_id": f"{family}-0", "expected_version": 1, "data": {"last": 3, "alpha": 4}}
            )
            call(
                f"{family}.update",
                {"record_id": f"{family}-0", "expected_version": 1, "data": {"must_not_commit": True}},
            )
            call(f"{family}.search", {"collection": collection, "limit": 1, "cursor": first["next_cursor"]})
            call(f"{family}.delete", {"record_id": f"new-{family}", "expected_version": 1})
            call(f"{family}.read", {"record_id": f"new-{family}"})
            call(
                f"{family}.create",
                {"collection": collection, "record_id": "bad-tenant", "tenant_id": "outside", "data": {}},
            )
            call(
                f"{family}.update",
                {"record_id": f"{family}-1", "expected_version": True, "data": {"bool_version": True}},
            )
        call("calendar.read", {"record_id": "acl-denied"})
        call("calendar.read", {"record_id": "public-read"})
        call("calendar.update", {"record_id": "public-read", "expected_version": 1, "data": {}})
        call("mail.read", {"record_id": "docs-0"})
        call("mail.read_attachment", {"record_id": "mail-0", "attachment_id": "attachment"})
        call("mail.read_attachment", {"record_id": "mail-0", "attachment_id": "missing"})
        call(
            "mail.create_draft", {"record_id": "draft", "data": {"body": "local", "recipients": ["local@example.test"]}}
        )
        call("mail.send", {"record_id": "draft", "expected_version": 1, "idempotency_key": "send-once"})
        call("mail.send", {"record_id": "draft", "expected_version": 1, "idempotency_key": "send-once"})
        call("mail.send", {"record_id": "draft", "expected_version": 2})
        call("mail.create_draft", {"record_id": "empty-draft", "data": {}})
        call("mail.send", {"record_id": "empty-draft", "expected_version": 1})
        for data in [
            {"recipients": ["external@example.com"]},
            {"attendees": ["external@example.com"]},
            {"recipients": "not-a-list"},
        ]:
            call("docs.update", {"record_id": "docs-0", "expected_version": 2, "data": data})
        call(
            "docs.set_permissions",
            {
                "record_id": "docs-0",
                "expected_version": 2,
                "permissions": ["reader", {"principal_id": "writer", "role": "editor"}],
                "visibility": "public",
            },
        )
        for permissions in [
            ["reader", "reader"],
            ["*"],
            [{"principal_id": "other-owner", "role": "owner"}],
            [{"principal_id": "x", "role": "unsupported"}],
            [{"principal_id": "x", "role": "reader", "extra": True}],
        ]:
            call("docs.set_permissions", {"record_id": "docs-0", "expected_version": 3, "permissions": permissions})
        call(
            "docs.set_permissions",
            {"record_id": "docs-0", "expected_version": 3, "permissions": [], "visibility": "invalid"},
        )
        call(
            "docs.set_permissions",
            {
                "record_id": "docs-0",
                "expected_version": 3,
                "permissions": [{"principal_id": "bench-user", "role": "reader"}],
                "visibility": "private",
            },
        )
        call("calendar.invite", {"record_id": "calendar-0", "expected_version": 2})
        call("chat.post", {"record_id": "message", "data": {"body": "delivered"}})
        call("unknown.read", {"record_id": "docs-0"})
        call("docs.unsupported", {"record_id": "docs-0", "expected_version": 4})
        output = {
            "schema": "gauntlet-python-world-parity.v1",
            "public_test_seed_base64": base64.b64encode(SEED).decode(),
            "public_key": world.public_key(),
            "initial_snapshot_json": json.dumps(initial),
            "cases": cases,
            "final_snapshot": world.snapshot(),
            "receipts": world.receipts(),
            "source_sha256": {
                name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                for name in ["ci/gauntlet/benchmark/world.py", "ci/gauntlet/benchmark/json_data.py"]
            },
        }
    with DEST.open("x") as stream:
        json.dump(output, stream, sort_keys=True, indent=2, ensure_ascii=False)
        stream.write("\n")
    print(
        json.dumps(
            {
                "cases": len(cases),
                "accepted": sum("result" in c for c in cases),
                "refused": sum("error" in c for c in cases),
                "bytes": DEST.stat().st_size,
                "sha256": hashlib.sha256(DEST.read_bytes()).hexdigest(),
            }
        )
    )


if __name__ == "__main__":
    main()
