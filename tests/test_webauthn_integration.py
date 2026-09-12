from pathlib import Path

import pytest

from passkeytransit.webauthn_lab import run_webauthn_migration


EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")


@pytest.mark.skipif(not EDGE.is_file(), reason="Microsoft Edge/Chromium is unavailable")
def test_real_webauthn_assertion_after_cxf_migration(tmp_path):
    result = run_webauthn_migration(EDGE, tmp_path / "webauthn-result.json")
    assert result["all_checks_pass"]
    assert result["checks"]["assertion_signature"]
    assert result["checks"]["assertion_user_verified"]
    assert result["checks"]["large_blob"]
    assert result["checks"]["signature_counter_zero"]

