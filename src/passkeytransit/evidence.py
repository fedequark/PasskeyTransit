from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


CHALLENGE_DOMAIN = b"passkeytransit-webauthn-attempt-binding-v1\x00"
ATTEMPT_BINDING_FIELDS = (
    "protocol_id",
    "campaign_id",
    "run_id",
    "attempt_id",
    "credential_id_hash",
    "feature_stratum",
    "route_id",
    "repetition",
    "provider_chain",
)


def _unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def browser_attempt_binding(row: dict[str, Any]) -> dict[str, Any]:
    missing = [name for name in ATTEMPT_BINDING_FIELDS if name not in row]
    if missing:
        raise ValueError(f"browser attempt binding is missing fields: {missing}")
    return {name: row[name] for name in ATTEMPT_BINDING_FIELDS}


def derive_browser_challenge(nonce: bytes, binding: dict[str, Any]) -> bytes:
    if len(nonce) != 32:
        raise ValueError("browser challenge nonce must contain 32 bytes")
    return hashlib.sha256(CHALLENGE_DOMAIN + nonce + _canonical(binding)).digest()


def verify_browser_evidence(
    evidence: dict[str, Any], *, expected_attempt_binding: dict[str, Any] | None = None
) -> dict[str, bool]:
    transcript = evidence["transcript"]
    expected_ref = "sha256:" + hashlib.sha256(_canonical(transcript)).hexdigest()
    if evidence.get("transcript_ref") != expected_ref:
        raise ValueError("browser transcript commitment mismatch")
    binding = transcript.get("attempt_binding")
    if not isinstance(binding, dict):
        raise ValueError("browser transcript has no attempt binding")
    if expected_attempt_binding is not None and binding != expected_attempt_binding:
        raise ValueError("browser transcript is not bound to its attempt context")
    nonce = _unb64url(transcript["challenge_nonce"])
    derived_challenge = derive_browser_challenge(nonce, binding)
    if _unb64url(transcript["expected_challenge"]) != derived_challenge:
        raise ValueError("browser transcript challenge does not commit to its attempt context")

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
        "credential_row_binding": hashlib.sha256(raw_id).hexdigest() == binding["credential_id_hash"],
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


def _verify_large_blob_evidence(row: dict[str, Any], evidence: dict[str, Any]) -> None:
    extension = evidence.get("extensions", {}).get("large_blob")
    if not isinstance(extension, dict):
        raise ValueError("browser evidence has no retained largeBlob observation")
    expected = _unb64url(extension["expected"]) if extension.get("expected") is not None else None
    observed = _unb64url(extension["observed"]) if extension.get("observed") is not None else None
    applicable = bool(extension.get("applicable"))
    expected_applicable = row.get("feature_stratum") in {"F3", "F6"}
    if applicable != expected_applicable:
        raise ValueError("retained largeBlob applicability does not match the registered stratum")
    status = "PASS" if applicable and expected == observed else "FAIL" if applicable else "NOT_APPLICABLE"
    oracle = row.get("oracles", {}).get("large_blob", {})
    if oracle.get("status") != status:
        raise ValueError("retained largeBlob observation does not reproduce its oracle status")
    if applicable:
        hashes_observed = [
            hashlib.sha256(expected or b"").hexdigest(),
            hashlib.sha256(observed or b"").hexdigest(),
        ]
        if oracle.get("evidence") != hashes_observed:
            raise ValueError("retained largeBlob observation does not reproduce oracle evidence")
    extension_ref = "sha256:" + hashlib.sha256(_canonical(extension)).hexdigest()
    if evidence.get("extension_ref") != extension_ref:
        raise ValueError("browser extension evidence commitment mismatch")


def _audit_browser_sources(
    sources: Iterable[tuple[str, Iterable[str]]]
) -> dict[str, Any]:
    imported = 0
    rejected = 0
    files = 0
    challenges: set[bytes] = set()
    attempt_bindings = 0
    large_blob_oracles = 0
    for label, lines in sources:
        name = Path(label).name
        if not name.startswith("c1_phase7_") or not name.endswith("_attempts.jsonl"):
            continue
        files += 1
        for line_number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("execution_status") == "IMPORTED":
                evidence = row.get("browser_evidence")
                if not isinstance(evidence, dict):
                    raise ValueError(f"missing browser evidence: {label}:{line_number}")
                checks = verify_browser_evidence(
                    evidence, expected_attempt_binding=browser_attempt_binding(row)
                )
                if not all(checks.values()):
                    raise ValueError(f"browser verification failed: {label}:{line_number}")
                _verify_large_blob_evidence(row, evidence)
                attempt_bindings += 1
                large_blob_oracles += 1
                challenge = _unb64url(evidence["transcript"]["expected_challenge"])
                if len(challenge) < 16:
                    raise ValueError(f"browser challenge has insufficient entropy length: {label}:{line_number}")
                if challenge in challenges:
                    raise ValueError(f"browser challenge was reused: {label}:{line_number}")
                challenges.add(challenge)
                imported += 1
            elif row.get("execution_status") == "REJECTED":
                if row.get("browser_evidence") is not None:
                    raise ValueError(f"rejected row has browser evidence: {label}:{line_number}")
                rejected += 1
    if files == 0:
        raise ValueError("release contains no browser C1 attempt evidence")
    return {
        "files": files,
        "imported_transcripts_verified": imported,
        "unique_challenges_verified": len(challenges),
        "attempt_bindings_verified": attempt_bindings,
        "large_blob_oracles_recomputed": large_blob_oracles,
        "rejected_without_ceremony": rejected,
        "passed": True,
    }


def audit_browser_evidence(paths: Iterable[Path]) -> dict[str, Any]:
    sources: list[tuple[str, Iterable[str]]] = []
    for path in paths:
        if path.name.startswith("c1_phase7_") and path.name.endswith("_attempts.jsonl"):
            sources.append((str(path), path.read_text(encoding="utf-8").splitlines()))
    return _audit_browser_sources(sources)


def audit_browser_evidence_payloads(
    payloads: Iterable[tuple[str, bytes]]
) -> dict[str, Any]:
    return _audit_browser_sources(
        (name, payload.decode("utf-8").splitlines()) for name, payload in payloads
    )
