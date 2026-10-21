"""Compare a pinned public CXP type snapshot with our working-draft fixture.

This is source-schema analysis, not execution of the external Rust library.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from passkeytransit.cxp_wire_probe import synthetic_fixture  # noqa: E402


def analyze() -> dict[str, object]:
    source = ROOT / "experiments/cxp_external_schema/bitwarden_protocol_snapshot.json"
    snapshot = json.loads(source.read_text(encoding="utf-8"))
    request, response = synthetic_fixture()
    request_fields = set(snapshot["export_request_fields"])
    response_fields = set(snapshot["export_response_fields"])
    return {
        "source": snapshot["source"],
        "source_scope": snapshot["source_scope"],
        "request_fields_absent_from_upstream_types": sorted(set(request) - request_fields),
        "response_fields_absent_from_upstream_types": sorted(set(response) - response_fields),
        "upstream_version_storage_bits": snapshot["version_storage_bits"],
        "draft_version_storage_bits": 16,
        "interpretation": (
            "Pinned Rust types do not declare the archive and mode request fields or "
            "archive response field shown in the 2024 working draft. Serde may ignore "
            "unknown fields; this check does not establish a runtime rejection, "
            "HPKE/JWE interoperability, or a provider transfer."
        ),
    }


if __name__ == "__main__":
    output = ROOT / "experiments/cxp_external_schema/report.json"
    output.write_text(json.dumps(analyze(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
