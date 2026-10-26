"""Check retained same-codebase RP control report consistency."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = "fee19d9ac392ffe0153bea8b917aa0a66f12b272"
CASES = {("indirect", "spec-minimal"), ("direct", "spec-minimal"),
         ("indirect", "hardened"), ("direct", "hardened")}


def verify(report_path: Path) -> dict:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    probe = ROOT / "interop/cxp_poc2_cross_probe/pt-rp-control.ts"
    if report["status"] != "SAME_CODEBASE_RP_CONTROL_PASS" or report["source_commit"] != PIN:
        raise ValueError("status or pin differs")
    if report["probe_sha256"] != hashlib.sha256(probe.read_bytes()).hexdigest():
        raise ValueError("probe differs")
    if {(x["mode"], x["profile"]) for x in report["cases"]} != CASES or len(report["cases"]) != 4:
        raise ValueError("cases differ")
    for case in report["cases"]:
        if not all(case[k] is True for k in ("registered", "source_login_before", "target_login_after",
                                            "source_login_after", "same_credential_id")):
            raise ValueError("RP ceremony failed")
        if case["imported_passkeys"] != 1 or case["skipped"] != 0 or case["rp_registered_credentials"] != 1:
            raise ValueError("import or RP credential count differs")
        if "same-codebase" not in case["scope"]:
            raise ValueError("case scope missing")
    if "does not import cxporter ciphertext" not in report["limitation"]:
        raise ValueError("cross-implementation limitation missing")
    return {"status": "PASS", "cases": 4, "scope": "report consistency; pinned-source replay required"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=ROOT / "experiments/cxporter_cxp_open/poc2_rp_control.json")
    args = parser.parse_args()
    print(json.dumps(verify(args.report), sort_keys=True))


if __name__ == "__main__":
    main()
