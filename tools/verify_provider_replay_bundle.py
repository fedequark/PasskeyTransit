"""Verify a clean extraction of the 2026-10-26 local provider replay."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def verify(root: Path) -> dict[str, object]:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    for name, expected in manifest["files"].items():
        path = root / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"missing or changed member: {name}")
    sys.path[:0] = [str(root / "src"), str(root / "tools")]
    from passkeytransit.fenko_verify import verify_fenko_report
    from passkeytransit.fenko_roundtrip_verify import verify_fenko_roundtrip
    from verify_proton_public_report import verify_report as verify_proton

    fenko = verify_fenko_report(root / "reports/fenko_provider.json", root / "experiments/protocol_v2.json")
    roundtrip = verify_fenko_roundtrip(
        root / "reports/fenko_roundtrip.json", root / "experiments/protocol_v2_fenko_roundtrip.json"
    )
    proton = verify_proton(json.loads((root / "reports/proton_cxf_prf.json").read_text(encoding="utf-8")))
    if not (fenko["verified"] and roundtrip["verified"]):
        raise ValueError("Fenko public transcript verification failed")
    if not (
        fenko["summary"]["signed_assertions_verified"] == 16
        and fenko["summary"]["prf_witness_bindings_verified"] == 6
        and roundtrip["summary"]["signed_assertions_verified"] == 24
        and roundtrip["summary"]["prf_witness_bindings_verified"] == 12
        and proton["public_signatures_verified"] == 12
        and proton["public_prf_digests_verified"] == 12
    ):
        raise ValueError("public evidence counts differ")
    return {
        "status": "PASS",
        "hashed_members": len(manifest["files"]),
        "fenko_signatures": 16,
        "fenko_roundtrip_signatures": 24,
        "proton_signatures": 12,
        "fenko_prf_witnesses": 6,
        "fenko_roundtrip_prf_witnesses": 12,
        "proton_prf_digest_checks": 12,
        "scope": manifest["evidence_scope"],
    }


if __name__ == "__main__":
    print(json.dumps(verify(Path(__file__).resolve().parent), indent=2, sort_keys=True))
