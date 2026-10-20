"""Verify the retained Phase 14 CI artifact and its scoped public reports."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIR = ROOT / "experiments/phase14_ci_replay/2026-10-20"
PROVENANCE = DIR / "provenance.json"
ARTIFACT = DIR / "phase14-replay-39441456590.zip"
EXPECTED_CHECK_COUNTS = {"cross_runtime_cxp.json": 6, "prf_migration.json": 9}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify() -> dict[str, object]:
    provenance = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    if provenance["schema_version"] != 1 or provenance["status"] != "completed":
        raise ValueError("Unexpected replay provenance")
    if provenance["workflow_conclusion"] != "success":
        raise ValueError("Workflow did not complete successfully")
    if provenance["workflow_run_id"] != 39441456590 or provenance["artifact_id"] != 12275116897:
        raise ValueError("Unexpected workflow or artifact identity")
    if digest(ARTIFACT.read_bytes()) != provenance["artifact_sha256"]:
        raise ValueError("Downloaded artifact digest mismatch")
    prefix = provenance["artifact_run_directory"] + "/"
    expected_entries = {prefix + name for name in EXPECTED_CHECK_COUNTS}
    reports: dict[str, dict] = {}
    with zipfile.ZipFile(ARTIFACT) as archive:
        if archive.testzip() is not None or set(archive.namelist()) != expected_entries:
            raise ValueError("Artifact ZIP integrity or file set mismatch")
        for name, count in EXPECTED_CHECK_COUNTS.items():
            retained = (DIR / name).read_bytes()
            if retained != archive.read(prefix + name):
                raise ValueError(f"Retained report differs from artifact: {name}")
            if digest(retained) != provenance["reports"][name]:
                raise ValueError(f"Report digest mismatch: {name}")
            report = json.loads(retained)
            checks = report.get("checks")
            if report.get("all_checks_pass") is not True or not isinstance(checks, dict):
                raise ValueError(f"Failed or missing checks: {name}")
            if len(checks) != count or any(value is not True for value in checks.values()):
                raise ValueError(f"Check count or value mismatch: {name}")
            if report["node_script_sha256"] != digest((ROOT / "interop/node_cxp_exchange.mjs").read_bytes()):
                raise ValueError(f"Node script hash differs: {name}")
            runner_path = (ROOT / "src/passkeytransit/cross_runtime.py") if name == "cross_runtime_cxp.json" else (
                DIR / "prf_migration_runner.py"
            )
            if report["python_runner_sha256"] != digest(runner_path.read_bytes()):
                raise ValueError(f"Python runner hash differs: {name}")
            if report["node_version"] != provenance["environment"]["node_version"]:
                raise ValueError(f"Node version mismatch: {name}")
            reports[name] = report
    if reports["prf_migration.json"]["browser_version"] != provenance["environment"]["browser_version"]:
        raise ValueError("Browser version mismatch")
    if reports["cross_runtime_cxp.json"]["protocol_sha256"] != digest(
        (ROOT / "experiments/protocol_v1.5.json").read_bytes()
    ):
        raise ValueError("Protocol hash mismatch")
    if reports["prf_migration.json"]["checks"]["destination_prf_result_missing"] is not True:
        raise ValueError("Expected PRF loss control is absent")
    return {
        "artifact_sha256_verified": True,
        "reports_byte_equal_to_artifact": 2,
        "check_outcomes_recorded_true": sum(EXPECTED_CHECK_COUNTS.values()),
        "implementation_hashes_verified": 4,
        "browser_version": provenance["environment"]["browser_version"],
    }


if __name__ == "__main__":
    print(json.dumps(verify(), sort_keys=True))
