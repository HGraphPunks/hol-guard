"""Shared bounded policy objects for published and installed release data."""

# pyright: reportImplicitRelativeImport=false

from __future__ import annotations

import hashlib

from command_pack_store import MAX_OBJECT_BYTES, PackReader
from extension_delivery_objects import entries
from extension_pack_archives import pack_objects, parts


def policy_transport(reader, reference, records, store):
    """Mirror the native index without copying a corpus proof into each record."""
    if reference["kind"] != "data" or reference["expanded_length"] > MAX_OBJECT_BYTES:
        raise ValueError("native index representation unsupported")
    native = store.put(reader.blob(reference))
    if {key: native[key] for key in reference} != reference:
        raise ValueError("native index transport identity differs")
    page = reader.json(reference)
    output = {"schema": "guard.policy-transport.v2", "native": native, "kind": page["kind"]}
    if page["kind"] == "leaf":
        output["records"] = [[identity, records[identity]] for identity, _ in page["entries"]]
    else:
        output["children"] = [
            [prefix, count, policy_transport(reader, target, records, store)]
            for prefix, count, target in page["children"]
        ]
    return store.put_json(output)


def build_policy(pack_directory, native_root, plan, store):
    """Package native outputs without interpreting or granting matcher authority."""
    reader = PackReader(pack_directory / "objects")
    inventory = dict(entries(reader, native_root["index"], native_root["extensions"]))
    if len(inventory) != native_root["extensions"]:
        raise ValueError("native policy inventory is incomplete")
    records, defaults = {}, {}
    for identity, reference in sorted(inventory.items()):
        # pack_objects records every object read by its reader. Each archive
        # needs a fresh read set, including any nodes shared with other packs.
        manifest, objects = pack_objects(PackReader(pack_directory / "objects"), reference)
        archives = []
        for data in parts(pack_directory / "objects", objects):
            archives.append(
                {"sha256": hashlib.sha256(data).hexdigest(), "length": len(data), "location": plan.asset(data, "pack")}
            )
        catalog = reader.json(manifest["catalog"])[0]
        if manifest["extension_id"] != identity or catalog["extension_id"] != identity:
            raise ValueError("native policy ownership differs")
        record = {
            "schema": "guard.policy-delivery.v2",
            "extension_id": identity,
            "manifest": reference,
            "catalog_metadata": store.put_json([catalog]),
            "archives": archives,
            "dependencies": catalog["dependencies"],
            "related_interfaces": sorted(manifest["related_interfaces"]),
            "required": catalog["required"],
            "activation": catalog["activation"],
            "trust_class": catalog["trust_class"],
        }
        records[identity] = store.put_json(record)
        if catalog["enabled"]:
            if catalog["trust_class"] == "external":
                raise ValueError("external policy cannot be selected by release defaults")
            defaults[identity] = records[identity]
    return {
        "root": native_root,
        "transport": policy_transport(reader, native_root["index"], records, store),
        "defaults": {"count": len(defaults), "index": store.index(defaults) if defaults else None},
    }
