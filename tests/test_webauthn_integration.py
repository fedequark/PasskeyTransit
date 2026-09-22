from pathlib import Path

import pytest

from passkeytransit.webauthn_lab import run_webauthn_migration
import hashlib
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from passkeytransit.browser_campaign import ASSERT_CHALLENGE, _verify, run_browser_c1
from passkeytransit.campaign import _passkey, build_c1_corpus
from passkeytransit.model import b64url, unb64url


EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")


def test_invalid_assertion_signature_is_recorded_as_failure():
    protocol = json.loads((Path(__file__).parents[1] / "experiments" / "protocol_v1.0.json").read_text())
    source = build_c1_corpus(protocol)[0][2]
    key = _passkey(source)
    origin = f"https://{key['rpId']}"
    client_json = json.dumps({
        "type": "webauthn.get", "challenge": b64url(ASSERT_CHALLENGE), "origin": origin,
    }, separators=(",", ":")).encode()
    authenticator_data = hashlib.sha256(key["rpId"].encode()).digest() + bytes([0x05]) + bytes(4)
    private_key = serialization.load_der_private_key(unb64url(key["key"]), password=None)
    signature = bytearray(private_key.sign(authenticator_data + hashlib.sha256(client_json).digest(), ec.ECDSA(hashes.SHA256())))
    signature[-1] ^= 1
    assertion = {
        "rawId": key["credentialId"], "userHandle": key["userHandle"],
        "authenticatorData": b64url(authenticator_data), "clientDataJSON": b64url(client_json),
        "signature": b64url(bytes(signature)),
    }
    checks = _verify(assertion, key, origin)
    assert checks["signature"] is False


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
    assert summary["execution_statuses"] == {"IMPORTED": 80, "REJECTED": 16}
    assert summary["oracle_statuses"]["webauthn_assertion"] == {"PASS": 80, "NOT_APPLICABLE": 16}
    assert summary["oracle_statuses"]["uv"] == {"PASS": 80, "NOT_APPLICABLE": 16}
    assert summary["oracle_statuses"]["large_blob"] == {"PASS": 11, "FAIL": 8, "NOT_APPLICABLE": 77}
    assert result["manifest"]["cdp"]["protocol_version"]
    assert len(result["manifest"]["cdp"]["schema_sha256"]) == 64
    assert len(result["manifest"]["dependency_lock_sha256"]) == 64
    rows = [json.loads(line) for line in (tmp_path / "c1_phase7_calibration_attempts.jsonl").read_text().splitlines()]
    imported = next(row for row in rows if row["execution_status"] == "IMPORTED")
    evidence = imported["browser_evidence"]
    transcript = evidence["transcript"]
    canonical = json.dumps(transcript, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    assert evidence["transcript_ref"] == "sha256:" + hashlib.sha256(canonical).hexdigest()
    public_key = serialization.load_der_public_key(unb64url(transcript["source_public_key_spki"]))
    public_key.verify(
        unb64url(transcript["signature"]),
        unb64url(transcript["authenticatorData"]) + hashlib.sha256(unb64url(transcript["clientDataJSON"])).digest(),
        ec.ECDSA(hashes.SHA256()),
    )
