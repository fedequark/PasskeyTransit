"""Check retained adapter-to-RP report and scope; replay checks execution."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify(report_path: Path) -> dict:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report["status"] != "PROJECT_ADAPTER_RP_CONTROL_PASS":
        raise ValueError("status differs")
    if report["source_commits"] != {
        "cxporter": "96bab31fdadcfd295542bba86b8ec8bd2355294a",
        "cxp_poc2": "fee19d9ac392ffe0153bea8b917aa0a66f12b272",
    }:
        raise ValueError("source pins differ")
    for field, path in (
        ("probe_sha256", "interop/cxp_poc2_cross_probe/pt-adapter-rp.ts"),
        ("helper_sha256", "tools/cxporter_to_poc2_rp_adapter.py"),
    ):
        if report[field] != hashlib.sha256((ROOT / path).read_bytes()).hexdigest():
            raise ValueError(f"{field} differs")
    if len(report["runs"]) != 2:
        raise ValueError("run count differs")
    digests = set()
    for run in report["runs"]:
        if run["status"] != "ADAPTER_RP_CONTROL_PASS" or run["response_has_archive"] is not False:
            raise ValueError("export status or archive field differs")
        if run["project_adapter_inserted_records"] != 1 or not run["rp_verified_before_and_after"] or not run["same_credential_id"]:
            raise ValueError("vault or RP assertion differs")
        digest = run["archive_sha256"]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid archive digest")
        digests.add(digest)
        if "PoC CXP importer not called" not in run["limitation"]:
            raise ValueError("run scope missing")
    if len(digests) != 2 or "bypass PoC CXP importer" not in report["limitation"]:
        raise ValueError("freshness or report scope missing")
    return {"status": "PASS", "runs": 2, "scope": "report consistency; pinned-source replay required"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=ROOT / "experiments/cxporter_cxp_open/adapter_rp_control.json")
    args = parser.parse_args()
    print(json.dumps(verify(args.report), sort_keys=True))


if __name__ == "__main__":
    main()
