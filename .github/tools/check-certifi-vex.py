"""Bind a narrow patched-certifi VEX to the exact locked PyPI artifacts.

The upstream advisory patches 2026.10.18; the Trivy DB used by CI currently
reports 2026.10.19 as its fixed threshold. A changed lockfile must fail this
check until the VEX is reviewed again. This never waives other findings.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VEX = ROOT / ".github/tools/certifi-2026.10.18.openvex.json"
LOCK = ROOT / "uv.lock"
SDIST_SHA = "sha256:b9995d97b64d0431a5af837d8ca8cd6238104d1f319f04bd93ea43124d6c861e"
WHEEL_SHA = "sha256:73191c47aaa79da394e8fee2dbc2ec827432cab56311122c9e47abf79e390f62"
ADVISORY = "GHSA-6q48-6c7w-9gw2"
PURL = "pkg:pypi/certifi@2026.10.18"


def check() -> None:
    lock = tomllib.loads(LOCK.read_text(encoding="utf-8"))
    certifi = [package for package in lock["package"] if package["name"] == "certifi"]
    if len(certifi) != 1:
        raise ValueError("uv.lock must contain exactly one certifi package")
    package = certifi[0]
    if (package["version"] != "2026.10.18"
            or package["source"] != {"registry": "https://pypi.org/simple"}
            or package["sdist"]["hash"] != SDIST_SHA
            or len(package["wheels"]) != 1
            or package["wheels"][0]["hash"] != WHEEL_SHA
            or not package["sdist"]["url"].endswith("/certifi-2026.10.18.tar.gz")
            or not package["wheels"][0]["url"].endswith("/certifi-2026.10.18-py3-none-any.whl")):
        raise ValueError("certifi lock differs from the reviewed patched artifacts")
    vex = json.loads(VEX.read_text(encoding="utf-8"))
    if (vex.get("@context") != "https://openvex.dev/ns/v0.2.0"
            or vex.get("author") != "HOL Guard maintainers"
            or vex.get("version") != 1
            or len(vex.get("statements", [])) != 1):
        raise ValueError("certifi OpenVEX document differs from the reviewed statement")
    statement = vex["statements"][0]
    if (statement.get("vulnerability") != {"name": ADVISORY}
            or statement.get("products") != [{"@id": PURL}]
            or statement.get("status") != "fixed"
            or SDIST_SHA.removeprefix("sha256:") not in statement.get("impact_statement", "")
            or WHEEL_SHA.removeprefix("sha256:") not in statement.get("impact_statement", "")):
        raise ValueError("certifi OpenVEX does not bind the reviewed advisory and product")
    print("Verified exact patched certifi 2026.10.18 artifacts and narrow OpenVEX statement")


if __name__ == "__main__":
    check()
