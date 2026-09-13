from pathlib import Path

import pytest

from passkeytransit.webauthn_lab import run_webauthn_migration
from passkeytransit.browser_campaign import run_browser_c1


EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")


@pytest.mark.skipif(not EDGE.is_file(), reason="Microsoft Edge/Chromium is unavailable")
def test_real_webauthn_assertion_after_cxf_migration(tmp_path):
    result = run_webauthn_migration(EDGE, tmp_path / "webauthn-result.json")
    assert result["all_checks_pass"]
    assert result["checks"]["assertion_signature"]
    assert result["checks"]["assertion_user_verified"]
    assert result["checks"]["large_blob"]
    assert result["checks"]["signature_counter_zero"]


@pytest.mark.skipif(not EDGE.is_file(), reason="Microsoft Edge/Chromium is unavailable")
def test_phase7_browser_calibration(tmp_path):
    protocol = Path(__file__).parents[1] / "experiments" / "protocol_v1.0.json"
    result = run_browser_c1(protocol, EDGE, tmp_path, calibration=True)
    summary = result["summary"]
    assert summary["attempt_count"] == 96
    assert summary["oracle_statuses"]["webauthn_assertion"] == {"PASS": 96}
    assert summary["oracle_statuses"]["uv"] == {"PASS": 96}
    assert summary["oracle_statuses"]["large_blob"] == {
        "PASS": 12,
        "FAIL": 12,
        "NOT_APPLICABLE": 72,
    }
