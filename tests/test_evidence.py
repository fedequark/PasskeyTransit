from __future__ import annotations

import base64
import copy
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from passkeytransit.evidence import (
    audit_browser_evidence,
    browser_attempt_binding,
    derive_browser_challenge,
    verify_browser_evidence,
)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _row(attempt_id: str, credential_id: bytes = b"credential") -> dict:
    blob_hash = hashlib.sha256(b"blob").hexdigest()
    return {
        "protocol_id": "passkeytransit-semantic-preservation-v1.3",
        "campaign_id": "C1",
        "run_id": "phase7-browser-test-r1",
        "attempt_id": attempt_id,
        "credential_id_hash": hashlib.sha256(credential_id).hexdigest(),
        "feature_stratum": "F3",
        "route_id": "R01",
        "repetition": 1,
        "provider_chain": ["reference", "strict"],
        "execution_status": "IMPORTED",
        "oracles": {"large_blob": {"status": "PASS", "evidence": [blob_hash, blob_hash]}},
        "_credential_id": _b64url(credential_id),
    }


def _public_row(row: dict) -> dict:
    return {key: value for key, value in row.items() if not key.startswith("_")}


def _evidence(row: dict, *, nonce: bytes = b"n" * 32) -> dict:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_row = _public_row(row)
    binding = browser_attempt_binding(public_row)
    challenge = derive_browser_challenge(nonce, binding)
    rp_id = "rp.example.test"
    origin = "https://rp.example.test"
    credential_id = base64.urlsafe_b64decode(row["_credential_id"] + "==")
    user_handle = b"user"
    client_json = json.dumps(
        {"challenge": _b64url(challenge), "origin": origin, "type": "webauthn.get"},
        separators=(",", ":"),
    ).encode()
    authenticator_data = hashlib.sha256(rp_id.encode()).digest() + bytes([0x05]) + bytes(4)
    signature = private_key.sign(
        authenticator_data + hashlib.sha256(client_json).digest(), ec.ECDSA(hashes.SHA256())
    )
    transcript = {
        "rawId": _b64url(credential_id),
        "authenticatorData": _b64url(authenticator_data),
        "clientDataJSON": _b64url(client_json),
        "signature": _b64url(signature),
        "userHandle": _b64url(user_handle),
        "source_public_key_spki": _b64url(public_spki),
        "expected_credential_id": _b64url(credential_id),
        "expected_user_handle": _b64url(user_handle),
        "expected_challenge": _b64url(challenge),
        "challenge_nonce": _b64url(nonce),
        "attempt_binding": binding,
        "source_rp_id": rp_id,
        "expected_origin": origin,
    }
    checks = {name: True for name in (
        "credential_id", "credential_row_binding", "user_handle", "challenge", "origin", "type",
        "rp_id_hash", "user_present", "user_verified", "signature", "counter_zero",
    )}
    extension = {"applicable": True, "expected": _b64url(b"blob"), "observed": _b64url(b"blob")}
    return {
        "checks": checks,
        "transcript": transcript,
        "transcript_ref": "sha256:" + hashlib.sha256(
            json.dumps(transcript, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "extensions": {"large_blob": extension},
        "extension_ref": "sha256:" + hashlib.sha256(
            json.dumps(extension, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def test_retained_browser_transcript_is_independently_verifiable():
    row = _row("attempt-1")
    evidence = _evidence(row)
    assert verify_browser_evidence(
        evidence, expected_attempt_binding=browser_attempt_binding(_public_row(row))
    ) == evidence["checks"]


def test_browser_evidence_rejects_transcript_reassignment_even_after_rehash():
    source = _row("attempt-1")
    target = _row("attempt-2", b"different-credential")
    evidence = _evidence(source)
    target_binding = browser_attempt_binding(_public_row(target))
    with pytest.raises(ValueError, match="attempt context"):
        verify_browser_evidence(evidence, expected_attempt_binding=target_binding)

    forged = copy.deepcopy(evidence)
    forged["transcript"]["attempt_binding"] = target_binding
    forged["transcript_ref"] = "sha256:" + hashlib.sha256(
        json.dumps(forged["transcript"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(ValueError, match="challenge"):
        verify_browser_evidence(forged, expected_attempt_binding=target_binding)


def test_browser_evidence_audit_rejects_reused_challenge(tmp_path):
    row = _row("attempt-1")
    row["browser_evidence"] = _evidence(row)
    public = _public_row(row)
    path = tmp_path / "c1_phase7_full_attempts.jsonl"
    path.write_text(json.dumps(public) + "\n" + json.dumps(public) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="reused"):
        audit_browser_evidence([path])


def test_browser_evidence_audit_recomputes_large_blob_oracle(tmp_path):
    row = _row("attempt-1")
    row["oracles"]["large_blob"]["status"] = "FAIL"
    row["browser_evidence"] = _evidence(row)
    path = tmp_path / "c1_phase7_full_attempts.jsonl"
    path.write_text(json.dumps(_public_row(row)) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="largeBlob"):
        audit_browser_evidence([path])


def test_browser_evidence_audit_recomputes_large_blob_applicability(tmp_path):
    row = _row("attempt-1")
    row["browser_evidence"] = _evidence(row)
    row["browser_evidence"]["extensions"]["large_blob"]["applicable"] = False
    extension = row["browser_evidence"]["extensions"]["large_blob"]
    row["browser_evidence"]["extension_ref"] = "sha256:" + hashlib.sha256(
        json.dumps(extension, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    row["oracles"]["large_blob"] = {"status": "NOT_APPLICABLE", "evidence": None}
    path = tmp_path / "c1_phase7_full_attempts.jsonl"
    path.write_text(json.dumps(_public_row(row)) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="applicability"):
        audit_browser_evidence([path])
