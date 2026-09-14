from passkeytransit.oracle_capabilities import write_oracle_capability_report


def test_capability_report_keeps_blocked_oracles_out_of_positive_evidence(tmp_path):
    report = write_oracle_capability_report(tmp_path / "capabilities.json")
    assert "prf_uv" in report["open_behavioral_oracles"]
    assert "cxp_pqc" in report["open_behavioral_oracles"]
    assert all(
        item["status"] == "EXECUTED"
        for item in report["capabilities"]
        if item["oracle"] not in report["open_behavioral_oracles"]
    )
