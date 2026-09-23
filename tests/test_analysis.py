from __future__ import annotations

import hashlib
import json
from pathlib import Path

from passkeytransit.analysis import run_analysis


def _write_evidence(root: Path, name: str, summary: dict):
    summary_path = root / f"{name}-summary.json"
    manifest_path = root / f"{name}-manifest.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    manifest_path.write_text(
        json.dumps(
            {
                "summary_sha256": hashlib.sha256(summary_path.read_bytes()).hexdigest(),
                "source_dirty": False,
                "source_commit": "test-commit",
                "browser": {"version": "test-browser"},
                "playwright_version": "test-playwright",
            }
        ),
        encoding="utf-8",
    )
    return summary_path, manifest_path


def test_phase9_generates_hash_verified_claim_bounded_manuscript(tmp_path):
    estimand = {"numerator": 1, "denominator": 2, "estimate": 0.5, "ci95": [0.25, 0.75]}
    c1 = {
        "protocol_id": "passkeytransit-semantic-preservation-v1.1",
        "mode": "full", "attempt_count": 6144, "credential_count": 256, "route_count": 12,
        "repeat_equivalent": True,
        "execution_statuses": {"IMPORTED": 6144, "REJECTED": 0},
        "semantic_classes": {"PASS": 2304, "DEGRADED_VISIBLE": 1408, "DEGRADED_SILENT": 1920, "NOT_EVALUABLE": 512},
        "oracle_statuses": {"webauthn_assertion": {"PASS": 6144}},
        "estimands": {"preserving_migration_yield": estimand, "conditional_semantic_preservation": estimand, "silent_degradation_rate": estimand, "false_reassurance_rate": estimand},
    }
    c2 = {"protocol_id": "passkeytransit-semantic-preservation-v1.1", "attempt_count": 80, "mutation_families": {"m": {"attempts": 8, "execution_statuses": {}, "semantic_classes": {}, "normative_classes": {}}}}
    c3 = {"protocol_id": "passkeytransit-semantic-preservation-v1.1", "failure_sequence_count": 960, "event_count": 1920, "atomicity": {"PASS": 832, "FAIL": 128}, "by_destination_and_failure_point": {"legacy:before-commit": {"sequences": 64, "atomicity_failures": 64, "idempotence_failures": 64}}}
    c1_paths = _write_evidence(tmp_path, "c1", c1)
    c2_paths = _write_evidence(tmp_path, "c2", c2)
    c3_paths = _write_evidence(tmp_path, "c3", c3)
    interop = tmp_path / "interop.json"
    interop.write_text(json.dumps({"all_applicable_checks_pass": True, "git": {"source_dirty": False, "source_commit": "test-commit"}}), encoding="utf-8")
    output = tmp_path / "paper"
    result = run_analysis(*c1_paths, *c2_paths, *c3_paths, interop, output)
    manuscript = (output / "MANUSCRIPT.md").read_text(encoding="utf-8")
    assert "estímulos sintéticos diseñados" in manuscript
    assert "proveedores comerciales" in manuscript
    assert result["manifest"]["claim_boundary_enforced"] is True
    assert (output / "table_c1_estimands.csv").is_file()
    assert (output / "results_v0.3.json").is_file()
    assert (output / "analysis_manifest.json").is_file()
