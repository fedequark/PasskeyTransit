from passkeytransit.oracle_capabilities import write_oracle_capability_report


def test_capability_report_keeps_blocked_oracles_out_of_positive_evidence(tmp_path):
    report = write_oracle_capability_report(tmp_path / "capabilities.json")
    assert report["executed_behavioral_oracles"] == ["webauthn_assertion", "uv", "large_blob"]
    assert report["blocked_behavioral_oracles"] == ["prf_uv", "prf_no_uv", "cred_blob"]
    assert all(
        item["status"] == "EXECUTED"
        for item in report["capabilities"]
        if item["oracle"] in report["executed_behavioral_oracles"]
    )
    assert next(item for item in report["capabilities"] if item["oracle"] == "cxp_pqc")[
        "status"
    ] == "OUT_OF_SCOPE"
