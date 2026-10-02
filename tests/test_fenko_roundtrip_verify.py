import json
from pathlib import Path

from passkeytransit.fenko_roundtrip_verify import verify_fenko_roundtrip


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "experiments" / "v2_roundtrip_exploratory" / "fenko_roundtrip.json"
PROTOCOL = ROOT / "experiments" / "protocol_v2_fenko_roundtrip.json"


def test_retained_browser_roundtrip_recalculates() -> None:
    result = verify_fenko_roundtrip(REPORT, PROTOCOL)
    assert result["verified"]
    assert result["summary"] == {
        "repetitions": 2,
        "signed_assertions_verified": 24,
        "prf_witness_bindings_verified": 12,
        "functional_continuity_pass_runs": 2,
        "source_seed_mismatch_runs": 2,
        "missing_export_prf_state_runs": 2,
    }


def test_roundtrip_verifier_rejects_changed_signature_and_prf_digest(tmp_path: Path) -> None:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    report["runs"][0]["assertions"]["destination"]["first"]["signature"] = "AA"
    path = tmp_path / "bad_signature.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    assert not verify_fenko_roundtrip(path, PROTOCOL)["verified"]

    report = json.loads(REPORT.read_text(encoding="utf-8"))
    report["runs"][0]["assertions"]["source"]["first"]["prf_output_sha256"] = "00" * 32
    path = tmp_path / "bad_prf_digest.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    assert not verify_fenko_roundtrip(path, PROTOCOL)["verified"]


def test_roundtrip_verifier_rejects_changed_outcome(tmp_path: Path) -> None:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    report["runs"][0]["outcomes"]["fixed_source_destination_equal"] = False
    path = tmp_path / "bad_outcome.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    assert not verify_fenko_roundtrip(path, PROTOCOL)["verified"]
