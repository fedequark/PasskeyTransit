from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from passkeytransit.evidence import audit_browser_evidence, verify_browser_evidence


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def test_retained_browser_transcript_is_independently_verifiable():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    challenge = hashlib.sha256(b"challenge").digest()
    rp_id = "rp.example.test"
    origin = "https://rp.example.test"
    credential_id = b"credential"
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
        "expected_attempt_id": "attempt-1",
        "source_rp_id": rp_id,
        "expected_origin": origin,
    }
    checks = {
        "credential_id": True,
        "user_handle": True,
        "challenge": True,
        "origin": True,
        "type": True,
        "rp_id_hash": True,
        "user_present": True,
        "user_verified": True,
        "signature": True,
        "counter_zero": True,
    }
    evidence = {
        "checks": checks,
        "transcript": transcript,
        "transcript_ref": "sha256:" + hashlib.sha256(
            json.dumps(transcript, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }
    assert verify_browser_evidence(evidence, expected_attempt_id="attempt-1") == checks
    with pytest.raises(ValueError, match="attempt id"):
        verify_browser_evidence(evidence, expected_attempt_id="attempt-2")
    evidence["transcript"]["expected_origin"] = "https://other.example.test"
    with pytest.raises(ValueError):
        verify_browser_evidence(evidence)


def test_browser_evidence_audit_rejects_reused_challenge(tmp_path):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    challenge = hashlib.sha256(b"reused-challenge").digest()
    rp_id, origin = "rp.example.test", "https://rp.example.test"
    client_json = json.dumps(
        {"challenge": _b64url(challenge), "origin": origin, "type": "webauthn.get"},
        separators=(",", ":"),
    ).encode()
    authenticator_data = hashlib.sha256(rp_id.encode()).digest() + bytes([0x05]) + bytes(4)
    signature = private_key.sign(
        authenticator_data + hashlib.sha256(client_json).digest(), ec.ECDSA(hashes.SHA256())
    )
    rows = []
    for attempt_id in ("attempt-1", "attempt-2"):
        transcript = {
            "rawId": _b64url(b"credential"), "authenticatorData": _b64url(authenticator_data),
            "clientDataJSON": _b64url(client_json), "signature": _b64url(signature),
            "userHandle": _b64url(b"user"), "source_public_key_spki": _b64url(public_spki),
            "expected_credential_id": _b64url(b"credential"), "expected_user_handle": _b64url(b"user"),
            "expected_challenge": _b64url(challenge), "expected_attempt_id": attempt_id,
            "source_rp_id": rp_id, "expected_origin": origin,
        }
        checks = {name: True for name in (
            "credential_id", "user_handle", "challenge", "origin", "type", "rp_id_hash",
            "user_present", "user_verified", "signature", "counter_zero",
        )}
        rows.append({
            "attempt_id": attempt_id, "execution_status": "IMPORTED",
            "browser_evidence": {"checks": checks, "transcript": transcript,
                "transcript_ref": "sha256:" + hashlib.sha256(
                    json.dumps(transcript, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()},
        })
    path = tmp_path / "c1_phase7_full_attempts.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    with pytest.raises(ValueError, match="reused"):
        audit_browser_evidence([path])
