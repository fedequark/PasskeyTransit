"""Verify retained provider CI artifacts and their public cryptographic reports.

The provenance sidecar records GitHub's artifact digests. This offline check
confirms that the retained ZIPs have those bytes; it cannot attest GitHub's
identity or prove a transfer between installed provider applications.
"""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "experiments/provider_replays/2026-10-26/ci"
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tools")]

from passkeytransit.fenko_verify import verify_fenko_report  # noqa: E402
from passkeytransit.fenko_roundtrip_verify import verify_fenko_roundtrip  # noqa: E402
from verify_proton_public_report import verify_report as verify_proton  # noqa: E402


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify() -> dict[str, object]:
    provenance = json.loads((CI / "private_provenance.json").read_text(encoding="utf-8"))
    for name, record in provenance["artifacts"].items():
        archive = CI / name / "github-artifact.zip"
        if _sha(archive.read_bytes()) != record["github_archive_sha256"]:
            raise ValueError(f"GitHub artifact digest differs: {name}")
        with zipfile.ZipFile(archive) as zf:
            if zf.testzip() is not None or set(zf.namelist()) != set(record["reports"]):
                raise ValueError(f"invalid GitHub artifact members: {name}")
            for filename, expected in record["reports"].items():
                payload = zf.read(filename)
                if _sha(payload) != expected or payload != (CI / name / filename).read_bytes():
                    raise ValueError(f"report differs from GitHub artifact: {name}/{filename}")

    fenko = verify_fenko_report(
        CI / "fenko" / "fenko_provider.json", ROOT / "experiments/protocol_v2.json"
    )["summary"]
    roundtrip = verify_fenko_roundtrip(
        CI / "fenko" / "fenko_roundtrip.json",
        ROOT / "experiments/protocol_v2_fenko_roundtrip.json",
    )["summary"]
    proton = verify_proton(json.loads((CI / "proton" / "proton_cxf_prf.json").read_text()))
    counts = (
        fenko["signed_assertions_verified"], fenko["prf_witness_bindings_verified"],
        roundtrip["signed_assertions_verified"], roundtrip["prf_witness_bindings_verified"],
        proton["public_signatures_verified"], proton["public_prf_digests_verified"],
    )
    if counts != (16, 6, 24, 12, 12, 12):
        raise ValueError(f"unexpected public verifier counts: {counts}")
    return {
        "status": "PASS",
        "workflow_run": provenance["workflow_run_url"],
        "head_sha": provenance["head_sha"],
        "artifact_digest_matches": len(provenance["artifacts"]),
        "report_byte_matches": sum(len(item["reports"]) for item in provenance["artifacts"].values()),
        "fenko_signed_assertions": counts[0] + counts[2],
        "fenko_prf_bindings": counts[1] + counts[3],
        "proton_signed_assertions": counts[4],
        "proton_prf_bindings": counts[5],
        "scope": "same-team clean CI replays of pinned code; no independent investigator or provider-app CXP transfer",
    }


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2, sort_keys=True))
