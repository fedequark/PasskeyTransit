"""Write a reproducible, synthetic CXP working-draft shape report."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from passkeytransit.cxp_wire_probe import (  # noqa: E402
    WireShapeError,
    synthetic_fixture,
    validate_response,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "experiments/cxp_wire_structural/report.json",
    )
    args = parser.parse_args()
    request, response = synthetic_fixture()
    result = validate_response(request, response)
    mutations = {
        "version_mismatch": ("version", 1),
        "archive_not_offered": ("archive", "unknown"),
        "malformed_payload_encoding": ("payload", "bad+base64"),
    }
    negatives = {}
    for name, (field, value) in mutations.items():
        changed = copy.deepcopy(response)
        changed[field] = value
        try:
            validate_response(request, changed)
        except WireShapeError:
            negatives[name] = "REJECTED"
        else:
            negatives[name] = "ACCEPTED"
    if set(negatives.values()) != {"REJECTED"}:
        raise SystemExit("negative control unexpectedly accepted")
    report = {
        "profile": "synthetic-public-cxp-wd-20241003-structure-only",
        "source": "https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html",
        "fixture_sha256": hashlib.sha256(
            json.dumps({"request": request, "response": response}, sort_keys=True).encode()
        ).hexdigest(),
        "positive": result,
        "negative_controls": negatives,
        "limitations": [
            "JWE fixture uses direct AES-GCM, not HPKE",
            "working draft leaves HPKE-to-JWE binding and challenge-signature fields unspecified",
            "no CXF plaintext or external provider is decrypted or imported",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
