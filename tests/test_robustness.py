from __future__ import annotations

from pathlib import Path

from passkeytransit.robustness import _normative_class, run_c2_robustness, run_c3_faults


PROJECT_ROOT = Path(__file__).parents[1]
PROTOCOL_PATH = PROJECT_ROOT / "experiments" / "protocol_v1.3.json"


def test_c2_executes_every_frozen_mutation_for_every_stratum(tmp_path):
    result = run_c2_robustness(PROTOCOL_PATH, tmp_path)
    summary = result["summary"]
    assert summary["attempt_count"] == 80
    assert len(summary["mutation_families"]) == 10
    assert all(item["attempts"] == 8 for item in summary["mutation_families"].values())
    rejected = sum(item["execution_statuses"].get("REJECTED", 0) for item in summary["mutation_families"].values())
    assert rejected == 64
    assert summary["pooled_preservation_estimate"] is None
    raw = (tmp_path / "c2_phase6_attempts.jsonl").read_text(encoding="utf-8")
    assert "privateKeyPkcs8" not in raw
    assert "synthetic@example.test" not in raw
    assert len(raw.splitlines()) == 80


def test_c3_executes_registered_fault_sequences_and_retries(tmp_path):
    result = run_c3_faults(PROTOCOL_PATH, tmp_path)
    summary = result["summary"]
    assert summary["credential_count"] == 64
    assert summary["failure_sequence_count"] == 960
    assert summary["event_count"] == 1920
    assert summary["initial_execution_statuses"] == {"ROLLED_BACK": 832, "PARTIAL": 128}
    assert summary["final_execution_statuses"] == {"IMPORTED": 960}
    assert summary["atomicity"] == {"PASS": 832, "FAIL": 128}
    assert summary["idempotence"] == {"PASS": 832, "FAIL": 128}
    assert summary["by_destination_and_failure_point"]["legacy:before-commit"]["atomicity_failures"] == 64
    assert summary["by_destination_and_failure_point"]["strict:before-commit"]["atomicity_failures"] == 0
    assert len((tmp_path / "c3_phase6_sequences.jsonl").read_text(encoding="utf-8").splitlines()) == 960
    assert len((tmp_path / "c3_phase6_events.jsonl").read_text(encoding="utf-8").splitlines()) == 1920


def test_normative_class_uses_requirement_level_and_observed_oracle():
    oracles = {"public_key": {"status": "FAIL"}}
    must = {"id": "CXF-PK-007", "level": "MUST", "actor": "document"}
    should = {**must, "level": "SHOULD"}
    assert _normative_class(must, "IMPORTED", oracles, collision=False) == "VIOLATION"
    assert _normative_class(should, "IMPORTED", oracles, collision=False) == "AMBIGUOUS"
    assert _normative_class(None, "REJECTED", oracles, collision=True) == "AMBIGUOUS"
