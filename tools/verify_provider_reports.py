"""Recheck public Phase 14, Fenko, and Proton reports in a local package."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tools")]

from passkeytransit.fenko_verify import verify_fenko_report  # noqa: E402
from passkeytransit.fenko_roundtrip_verify import verify_fenko_roundtrip  # noqa: E402
from verify_phase14_public_transcript import verify as verify_phase14  # noqa: E402
from verify_proton_public_report import verify_report as verify_proton  # noqa: E402


def run() -> dict[str, object]:
    phase14 = verify_phase14(json.loads((
        ROOT / "experiments/phase14_ci_replay/2026-10-20/auditable/prf_migration.json"
    ).read_text(encoding="utf-8")))
    fenko = verify_fenko_report(
        ROOT / "experiments/v2_exploratory/fenko_provider.json",
        ROOT / "experiments/protocol_v2.json",
    )["summary"]
    roundtrip = verify_fenko_roundtrip(
        ROOT / "experiments/v2_roundtrip_exploratory/fenko_roundtrip.json",
        ROOT / "experiments/protocol_v2_fenko_roundtrip.json",
    )["summary"]
    proton = verify_proton(json.loads((
        ROOT / "experiments/phase17_exploratory/proton_cxf_prf.json"
    ).read_text(encoding="utf-8")))
    if not (
        phase14["signed_assertions_verified"] == 4
        and phase14["prf_digest_bindings_verified"] == 4
        and fenko["signed_assertions_verified"] == 16
        and fenko["prf_witness_bindings_verified"] == 6
        and roundtrip["signed_assertions_verified"] == 24
        and roundtrip["prf_witness_bindings_verified"] == 12
        and proton["public_signatures_verified"] == 12
        and proton["public_prf_digests_verified"] == 12
    ):
        raise ValueError("public report count mismatch")
    return {
        "phase14": phase14,
        "fenko": fenko,
        "fenko_roundtrip": roundtrip,
        "proton": proton,
        "scope": "public signatures and digest relationships; no provider provenance attestation",
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
