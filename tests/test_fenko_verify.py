import json
from pathlib import Path

from passkeytransit.fenko_verify import verify_fenko_report


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "experiments" / "v2_exploratory" / "fenko_provider.json"
PROTOCOL = ROOT / "experiments" / "protocol_v2.json"


def test_retained_external_provider_transcripts_verify() -> None:
    result = verify_fenko_report(REPORT, PROTOCOL)
    assert result["verified"]
    assert len(result["rows"]) == 2
    assert all(row["sensitive_absent"] for row in result["rows"])
    assert result["summary"] == {
        "repetitions": 2,
        "signed_assertions_verified": 16,
        "prf_witness_bindings_verified": 6,
        "source_prf_mismatch_runs": 2,
        "missing_export_prf_state_runs": 2,
        "bad_key_rejected_runs": 2,
        "duplicate_skipped_runs": 2,
        "restart_persisted_runs": 2,
    }


def test_verifier_rejects_signature_and_prf_witness_tampering(tmp_path: Path) -> None:
    source = json.loads(REPORT.read_text(encoding="utf-8"))
    source["runs"][0]["assertions"]["basic"]["signature"] = "AA"
    path = tmp_path / "bad_signature.json"
    path.write_text(json.dumps(source), encoding="utf-8")
    assert not verify_fenko_report(path, PROTOCOL)["verified"]
    source = json.loads(REPORT.read_text(encoding="utf-8"))
    source["runs"][0]["assertions"]["prf_first"]["prf_output_sha256"] = "00" * 32
    path = tmp_path / "bad_prf_witness.json"
    path.write_text(json.dumps(source), encoding="utf-8")
    assert not verify_fenko_report(path, PROTOCOL)["verified"]


def test_verifier_rejects_changed_source_or_export_summary(tmp_path: Path) -> None:
    source = json.loads(REPORT.read_text(encoding="utf-8"))
    source["runs"][0]["source_document_sha256"]["prf"] = "00" * 32
    path = tmp_path / "bad_source.json"
    path.write_text(json.dumps(source), encoding="utf-8")
    assert not verify_fenko_report(path, PROTOCOL)["verified"]

    source = json.loads(REPORT.read_text(encoding="utf-8"))
    source["runs"][0]["export"]["prf_extension_state_present"] = True
    path = tmp_path / "bad_export.json"
    path.write_text(json.dumps(source), encoding="utf-8")
    assert not verify_fenko_report(path, PROTOCOL)["verified"]
