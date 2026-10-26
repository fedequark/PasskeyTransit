"""Build a bounded differential of two pinned external CXP message parsers."""

from __future__ import annotations

import json
from pathlib import Path

from verify_cxp_runtime_report import verify as verify_rust
from verify_go_cxp_runtime_report import verify as verify_go

ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / "experiments/cxp_external_schema"


def compare() -> dict[str, object]:
    rust = verify_rust(REPORT_DIR / "runtime_report.json")
    go = verify_go(REPORT_DIR / "go_runtime_report.json")
    members = {
        "request.archive": "archive",
        "request.mode": "mode",
        "response.archive": "archive",
    }
    observations = {}
    for field, member in members.items():
        phase = "request" if field.startswith("request.") else "response"
        key = f"{phase}_fields_dropped_on_roundtrip"
        observations[field] = {
            "rust_preserved": member not in rust[key],
            "go_preserved": member not in go[key],
            "draft_field": "required",
        }
    return {
        "scope": "synthetic JSON type-parser round trips; no provider exchange or payload decryption",
        "fixture": "experiments/cxp_external_schema/fixture.json",
        "sources": {
            "rust": rust["source_commit"],
            "go": go["source_commit"],
        },
        "field_observations": observations,
        "version_256": {
            "rust_rejected": rust["draft_width_version_256_rejected"],
            "go_rejected": go["draft_width_version_256_rejected"],
            "interpretation": "fits draft 16-bit field but is not a published protocol version",
        },
        "hpke_jwe_decryption": "NOT_EVALUABLE",
        "provider_interoperability": "NOT_EVALUABLE",
    }


if __name__ == "__main__":
    report = compare()
    target = REPORT_DIR / "comparison.json"
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(target)
