from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def verify_browser_evidence(evidence: dict[str, Any]) -> dict[str, bool]:
    transcript = evidence["transcript"]
    expected_ref = "sha256:" + hashlib.sha256(_canonical(transcript)).hexdigest()
    if evidence.get("transcript_ref") != expected_ref:
        raise ValueError("browser transcript commitment mismatch")

    raw_id = _unb64url(transcript["rawId"])
    authenticator_data = _unb64url(transcript["authenticatorData"])
    client_json = _unb64url(transcript["clientDataJSON"])
    client = json.loads(client_json)
    signature = _unb64url(transcript["signature"])
    public_key = serialization.load_der_public_key(
        _unb64url(transcript["source_public_key_spki"])
    )
    signature_valid = True
    try:
        public_key.verify(
            signature,
            authenticator_data + hashlib.sha256(client_json).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature:
        signature_valid = False

    flags = authenticator_data[32]
    checks = {
        "credential_id": raw_id == _unb64url(transcript["expected_credential_id"]),
        "user_handle": _unb64url(transcript["userHandle"]) == _unb64url(transcript["expected_user_handle"]),
        "challenge": _unb64url(client["challenge"]) == _unb64url(transcript["expected_challenge"]),
        "origin": client["origin"] == transcript["expected_origin"],
        "type": client["type"] == "webauthn.get",
        "rp_id_hash": authenticator_data[:32] == hashlib.sha256(transcript["source_rp_id"].encode()).digest(),
        "user_present": bool(flags & 0x01),
        "user_verified": bool(flags & 0x04),
        "signature": signature_valid,
        "counter_zero": int.from_bytes(authenticator_data[33:37], "big") == 0,
    }
    if checks != evidence.get("checks"):
        raise ValueError("retained browser transcript does not reproduce recorded checks")
    return checks


def audit_browser_evidence(paths: Iterable[Path]) -> dict[str, Any]:
    imported = 0
    rejected = 0
    files = 0
    for path in paths:
        if not path.name.startswith("c1_phase7_") or not path.name.endswith("_attempts.jsonl"):
            continue
        files += 1
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if row.get("execution_status") == "IMPORTED":
                    evidence = row.get("browser_evidence")
                    if not isinstance(evidence, dict):
                        raise ValueError(f"missing browser evidence: {path}:{line_number}")
                    checks = verify_browser_evidence(evidence)
                    if not all(checks.values()):
                        raise ValueError(f"browser verification failed: {path}:{line_number}")
                    imported += 1
                elif row.get("execution_status") == "REJECTED":
                    if row.get("browser_evidence") is not None:
                        raise ValueError(f"rejected row has browser evidence: {path}:{line_number}")
                    rejected += 1
    if files == 0:
        raise ValueError("release contains no browser C1 attempt evidence")
    return {
        "files": files,
        "imported_transcripts_verified": imported,
        "rejected_without_ceremony": rejected,
        "passed": True,
    }
