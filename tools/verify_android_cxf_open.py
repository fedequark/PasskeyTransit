"""Check retained Android CXF source-audit evidence without vendor checkouts."""

from __future__ import annotations

import argparse
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "keyguard_conformance": ("keyguard-cxf-conformance.xml", 15, "passkey imports every member and forces the counter to zero[desktop]"),
    "keyguard_roundtrip": ("keyguard-cxf-roundtrip.xml", 29, "a login with a passkey and a totp round-trips[desktop]"),
    "monica_codec": ("monica-cxf-codec.xml", 18, "prfOrOtherUnimplementedExtensionsNeverLoseTheirSeedSilently"),
}


def verify(report_path: Path) -> dict:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report["status"] != "SOURCE_AUDIT_WITH_UPSTREAM_TESTS_PASS":
        raise ValueError("audit status differs")
    if report["source_commits"] != {
        "keyguard": "ef84e290665277866adcb7f061824de06f43ef9c",
        "monica": "5ef2f3a64b53094351210f1e316fbab51852708e",
    }:
        raise ValueError("provider pins differ")
    if set(report["upstream_xml"]) != set(EXPECTED):
        raise ValueError("upstream suite set differs")
    for key, (filename, count, selected) in EXPECTED.items():
        raw = (ROOT / "experiments/android_cxf_open/upstream" / filename).read_bytes()
        observed = report["upstream_xml"][key]
        if observed != {"sha256": hashlib.sha256(raw).hexdigest(), "tests": count, "selected_case": selected}:
            raise ValueError(f"upstream suite {key} metadata differs")
        suite = ET.fromstring(raw)
        if int(suite.attrib["tests"]) != count or any(int(suite.attrib[k]) for k in ("failures", "errors", "skipped")):
            raise ValueError(f"upstream suite {key} result differs")
        if selected not in {case.attrib["name"] for case in suite.findall("testcase")}:
            raise ValueError(f"upstream suite {key} selected case missing")
    if len(report["source_sha256"]) != 7 or any(len(value) != 64 for value in report["source_sha256"].values()):
        raise ValueError("source digest set differs")
    if "inferred from source" not in report["observations"]["keyguard"]:
        raise ValueError("Keyguard evidence scope missing")
    if "No Keyguard-to-Monica exchange" not in report["limitation"]:
        raise ValueError("cross-provider limitation missing")
    return {"status": "PASS", "upstream_suites": 3, "upstream_tests": 62,
            "scope": "upstream XML and source-hash consistency; pinned-source replay required"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=ROOT / "experiments/android_cxf_open/report.json")
    args = parser.parse_args()
    print(json.dumps(verify(args.report), sort_keys=True))


if __name__ == "__main__":
    main()
