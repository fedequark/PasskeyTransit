"""Verify provenance and scoped outcomes of the experimental ZIP/JWE runs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "experiments/cxp_zip_jwe_experimental"
SOURCES = {
    "profile": "src/passkeytransit/cxp_zip_jwe_profile.py",
    "hpke": "src/passkeytransit/hpke.py",
    "runner": "tools/run_cxp_zip_jwe_profile.py",
    "node_importer": "interop/node_cxp_zip_jwe.mjs",
    "python_exporter": "src/passkeytransit/cxp_zip_jwe_profile.py",
    "cross_runner": "tools/run_cxp_zip_jwe_cross_runtime.py",
}
EXPECTED_LOCAL = {
    "draft_zip_jwe_shape", "cxf_plaintext_recovered", "hmac_credentials_preserved",
    "modified_jwe_ciphertext_rejected", "modified_hpke_wrapped_key_rejected",
    "wrong_recipient_key_rejected", "unoffered_archive_rejected",
    "unexpected_exporter_rejected", "replay_rejected",
}
EXPECTED_CROSS = {
    "python_zip_jwe_export_node_import_equal",
    "node_rejects_modified_index_jwe_ciphertext",
    "node_rejects_modified_zip_central_crc",
    "node_rejects_wrong_recipient_key",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(root: Path = ROOT) -> dict[str, object]:
    reports = root / "experiments/cxp_zip_jwe_experimental"
    local = json.loads((reports / "report.json").read_text(encoding="utf-8"))
    cross = json.loads((reports / "cross_runtime.json").read_text(encoding="utf-8"))
    for report, expected in ((local, EXPECTED_LOCAL), (cross, EXPECTED_CROSS)):
        if report.get("profile") != "passkeytransit-cxp-zip-jwe-v1":
            raise ValueError("unexpected experimental profile")
        if report.get("all_checks_pass") is not True or report.get("checks") != dict.fromkeys(expected, True):
            raise ValueError("missing, failed, or unexpected ZIP/JWE control")
        if "external provider" not in " ".join(report.get("limitations", [])):
            raise ValueError("provider scope is not disclaimed")
    if local["document_sha256"] != cross["document_sha256"]:
        raise ValueError("local and cross-runtime synthetic documents differ")
    if local["archive_member_count"] != 2:
        raise ValueError("unexpected ZIP member count")
    for key, expected in local["source_sha256"].items():
        if key not in ("profile", "runner", "hpke") or sha((root / SOURCES[key]).read_bytes()) != expected:
            raise ValueError(f"local runner provenance mismatch: {key}")
    for key, expected in cross["source_sha256"].items():
        source = "cross_runner" if key == "runner" else key
        if source not in SOURCES or sha((root / SOURCES[source]).read_bytes()) != expected:
            raise ValueError(f"cross-runtime provenance mismatch: {key}")
    return {
        "status": "PASS",
        "local_controls": len(EXPECTED_LOCAL),
        "cross_runtime_controls": len(EXPECTED_CROSS),
        "scope": "project-authored synthetic HPKE/JWE binding; no external provider exchange",
    }


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2, sort_keys=True))
