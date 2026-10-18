"""Explicit authenticated preparation profiles, never authority from cache hashes."""

from __future__ import annotations

from importlib import import_module
from pathlib import Path

from ..extension_builder.io import read_bytes
from .authority import VerifiedDistribution
from .pack_store import PackReader, decode


def installed_bundle_type():
    try:
        module = import_module(".installed_bundle", __package__)
    except ModuleNotFoundError as exc:
        if exc.name != f"{__package__}.installed_bundle":
            raise
        return ()
    return module.VerifiedInstalledBundle


def load_installed_bundle():
    module = import_module(".installed_bundle", __package__)
    package = Path(__file__).absolute().parents[2]
    root = package / "guard/contracts/data/extensions/command-pack-bundle/command-pack-bundle.v1.json"
    manifests = [package / "_native" / name for name in ("runtime-manifest.json", "source-compiler-manifest.json")]

    def present(path):
        return path.exists() or path.is_symlink()

    # Source and old installations may have no bundle capability. Once either
    # manifest advertises one, absence/corruption must fail closed in the factory.
    if not present(root):
        if not any(present(path) for path in manifests):
            return None
        values = [decode(read_bytes(path, limit=65536)) for path in manifests]
        schemas = ("hol-guard-native-runtime.v1", "hol-guard-native-source-compiler.v2")
        if all(
            isinstance(value, dict) and value.get("schema") == schema and "command_pack_bundle" not in value
            for value, schema in zip(values, schemas, strict=True)
        ):
            return None
    return module.load_installed_bundle()


def publication(authority):
    from .activation_record import CommittedCommandPacks

    if type(authority) is VerifiedDistribution:
        return authority.manifest(), authority.data, authority.digest, "remote"
    if type(authority) is installed_bundle_type():
        return authority.manifest(), authority.data, authority.digest, "installed"
    if type(authority) is CommittedCommandPacks:
        record = authority.record()
        data = PackReader(authority.directory / "objects").blob(record["distribution"])
        return decode(data), data, record["root_digest"], "committed-subset"
    raise ValueError("pack preparation requires an authenticated publication")
