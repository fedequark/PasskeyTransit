from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


CHALLENGE_DOMAIN_V1 = b"passkeytransit-webauthn-attempt-binding-v1\x00"
CHALLENGE_DOMAIN_V2 = b"passkeytransit-webauthn-attempt-binding-v2\x00"
CHALLENGE_DOMAIN_V3 = b"passkeytransit-webauthn-attempt-binding-v3\x00"
ATTEMPT_BINDING_FIELDS_V1 = (
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
ATTEMPT_BINDING_FIELDS_V2 = ATTEMPT_BINDING_FIELDS_V1 + (
    "source_public_key_spki_sha256",
    "source_user_handle_sha256",
    "source_rp_id",
    "expected_origin",
)


def _unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def browser_attempt_binding(row: dict[str, Any]) -> dict[str, Any]:
    fields = (
        ATTEMPT_BINDING_FIELDS_V2
        if str(row.get("protocol_id", "")).endswith(("v1.4", "v1.5"))
        else ATTEMPT_BINDING_FIELDS_V1
    )
    missing = [name for name in fields if name not in row]
    if missing:
        raise ValueError(f"browser attempt binding is missing fields: {missing}")
    return {name: row[name] for name in fields}


def derive_browser_challenge(nonce: bytes, binding: dict[str, Any]) -> bytes:
    if len(nonce) != 32:
        raise ValueError("browser challenge nonce must contain 32 bytes")
    protocol_id = str(binding.get("protocol_id", ""))
    domain = (
        CHALLENGE_DOMAIN_V3
        if protocol_id.endswith("v1.5")
        else CHALLENGE_DOMAIN_V2
        if protocol_id.endswith("v1.4")
        else CHALLENGE_DOMAIN_V1
    )
    return hashlib.sha256(domain + nonce + _canonical(binding)).digest()


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
    public_spki = _unb64url(transcript["source_public_key_spki"])
    expected_user_handle = _unb64url(transcript["expected_user_handle"])
    if str(binding.get("protocol_id", "")).endswith(("v1.4", "v1.5")):
        if hashlib.sha256(public_spki).hexdigest() != binding["source_public_key_spki_sha256"]:
            raise ValueError("browser transcript public key is not bound to the source credential")
        if hashlib.sha256(expected_user_handle).hexdigest() != binding["source_user_handle_sha256"]:
            raise ValueError("browser transcript user handle is not bound to the source credential")
        if transcript["source_rp_id"] != binding["source_rp_id"]:
            raise ValueError("browser transcript RP ID is not bound to its attempt context")
        if transcript["expected_origin"] != binding["expected_origin"]:
            raise ValueError("browser transcript origin is not bound to its attempt context")
    public_key = serialization.load_der_public_key(public_spki)
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
        "user_handle": _unb64url(transcript["userHandle"]) == expected_user_handle,
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
    extensions = evidence.get("extensions")
    if not isinstance(extensions, dict):
        raise ValueError("browser evidence has no retained extensions")
    artifacts = evidence.get("artifact_sha256")
    if not isinstance(artifacts, dict):
        raise ValueError("browser evidence has no artifact hashes")
    large_blob = extensions.get("large_blob")
    artifact_values = {
        "rawId": transcript.get("rawId"),
        "authenticatorData": transcript.get("authenticatorData"),
        "clientDataJSON": transcript.get("clientDataJSON"),
        "signature": transcript.get("signature"),
        "userHandle": transcript.get("userHandle"),
        "largeBlob": large_blob.get("observed") if isinstance(large_blob, dict) else None,
        "prfFirst": extensions.get("prf_first"),
    }
    reproduced_artifacts = {
        name: hashlib.sha256(_unb64url(value)).hexdigest() if value is not None else None
        for name, value in artifact_values.items()
    }
    if artifacts != reproduced_artifacts:
        raise ValueError("browser artifact hashes do not reproduce retained evidence")
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
    extensions = evidence.get("extensions")
    committed_extension = (
        extensions
        if str(row.get("protocol_id", "")).endswith(("v1.4", "v1.5"))
        else extension
    )
    extension_ref = "sha256:" + hashlib.sha256(_canonical(committed_extension)).hexdigest()
    if evidence.get("extension_ref") != extension_ref:
        raise ValueError("browser extension evidence commitment mismatch")


def _verify_extension_witness(row: dict[str, Any], evidence: dict[str, Any]) -> bytes:
    witness = evidence.get("extension_witness")
    if not isinstance(witness, dict):
        raise ValueError("browser evidence has no signed extension witness")
    base_binding = browser_attempt_binding(row)
    primary_challenge = _unb64url(evidence["transcript"]["expected_challenge"])
    extensions = evidence.get("extensions")
    expected_binding = {
        **base_binding,
        "witness_for_challenge_sha256": hashlib.sha256(primary_challenge).hexdigest(),
        "extension_observation_sha256": hashlib.sha256(_canonical(extensions)).hexdigest(),
    }
    checks = verify_browser_evidence(witness, expected_attempt_binding=expected_binding)
    if not all(checks.values()):
        raise ValueError("signed extension witness verification failed")
    return _unb64url(witness["transcript"]["expected_challenge"])


def _audit_browser_sources(
    sources: Iterable[tuple[str, Iterable[str]]]
) -> dict[str, Any]:
    imported = 0
    rejected = 0
    files = 0
    challenges: set[bytes] = set()
    attempt_bindings = 0
    large_blob_oracles = 0
    source_bound_contexts = 0
    artifact_hash_sets = 0
    extension_witnesses = 0
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
                artifact_hash_sets += 1
                if str(row.get("protocol_id", "")).endswith("v1.4"):
                    source_bound_contexts += 1
                if str(row.get("protocol_id", "")).endswith("v1.5"):
                    source_bound_contexts += 1
                    witness_challenge = _verify_extension_witness(row, evidence)
                    if witness_challenge in challenges:
                        raise ValueError(f"browser witness challenge was reused: {label}:{line_number}")
                    challenges.add(witness_challenge)
                    extension_witnesses += 1
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
        "source_bound_contexts_verified": source_bound_contexts,
        "artifact_hash_sets_reproduced": artifact_hash_sets,
        "signed_extension_witnesses_verified": extension_witnesses,
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
