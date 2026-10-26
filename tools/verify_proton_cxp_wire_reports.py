"""Verify the archived, secret-free Proton CXP cross-implementation reports."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "experiments/proton_cxp_wire"
REVISION = "b22db5ca6fef03d0e9467c0305f9af8a2826be35"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _check(name: str, expected_controls: set[str]) -> dict:
    report = json.loads((REPORTS / name).read_text(encoding="utf-8"))
    assert report["status"] == "PASS", name
    assert report["external_revision"] == REVISION, name
    assert set(report["controls"]) == expected_controls, name
    assert all(value is True for value in report["controls"].values()), name
    assert report["limitations"], name
    for key, value in report.items():
        if key.endswith("_sha256"):
            assert isinstance(value, str) and SHA256.fullmatch(value), (name, key)
    assert all("private" not in key.lower() or isinstance(value, bool)
               for key, value in report["controls"].items()), name
    return report


def main() -> None:
    basic = _check(
        "proton-cxp-wire-report.json",
        {
            "synthetic_cxf_recovered",
            "altered_request_rejected",
            "wrong_recipient_rejected",
            "tampered_ciphertext_rejected",
        },
    )
    passkey = _check(
        "proton-cxp-passkey-report.json",
        {
            "credential_id_preserved",
            "rp_id_preserved",
            "private_key_preserved",
            "user_handle_preserved",
            "hmac_state_preserved",
            "changed_request_rejected",
            "destination_assertions_verified",
            "destination_prf_verified",
        },
    )
    assert passkey["signed_assertions_verified"] == 4
    assert passkey["prf_seed_checks_verified"] == 4
    print(json.dumps({"status": "PASS", "basic_controls": len(basic["controls"]),
                      "passkey_controls": len(passkey["controls"]),
                      "signed_assertions_verified": 4, "prf_seed_checks_verified": 4}, sort_keys=True))


if __name__ == "__main__":
    main()
