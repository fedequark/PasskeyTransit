from __future__ import annotations

import copy
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from passkeytransit.model import b64url
from tools.verify_phase14_public_transcript import verify


def report_fixture() -> dict:
    key = ec.generate_private_key(ec.SECP256R1())
    spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    credential = b"synthetic-credential"
    first_salt, other_salt = b"a" * 32, b"b" * 32
    first_digest, other_digest = hashlib.sha256(b"first-result").hexdigest(), hashlib.sha256(b"other-result").hexdigest()
    observations = []
    for index, (stage, salt, prf_digest) in enumerate((
        ("source_initial", first_salt, first_digest),
        ("source_repeat", first_salt, first_digest),
        ("source_other_salt", other_salt, other_digest),
        ("destination", first_salt, None),
    )):
        challenge = bytes([index + 1]) * 32
        client = json.dumps({"type": "webauthn.get", "challenge": b64url(challenge),
                             "origin": "http://localhost:12345"}).encode()
        auth = hashlib.sha256(b"localhost").digest() + b"\x05" + index.to_bytes(4, "big")
        signed = auth + hashlib.sha256(client).digest()
        signature = key.sign(signed, ec.ECDSA(hashes.SHA256()))
        observations.append({
            "stage": stage, "challenge": b64url(challenge), "salt": b64url(salt),
            "raw_id": b64url(credential), "authenticator_data": b64url(auth),
            "client_data_json": b64url(client), "signature": b64url(signature),
            "prf_present": prf_digest is not None, "prf_output_sha256": prf_digest,
        })
    return {
        "rp_id": "localhost", "credential_id_sha256": hashlib.sha256(credential).hexdigest(),
        "source_prf_output_sha256": first_digest, "all_checks_pass": True,
        "checks": {name: True for name in (
            "all_assertion_signatures_valid", "credential_id_preserved", "source_prf_executed",
            "same_salt_stable", "different_salt_changes_output", "destination_prf_result_missing")},
        "public_transcript": {"schema_version": 1, "rp_id": "localhost",
                              "credential_id": b64url(credential), "public_key_spki": b64url(spki),
                              "observations": observations},
    }


def test_recalculates_four_signatures_and_prf_bindings() -> None:
    assert verify(report_fixture())["signed_assertions_verified"] == 4


def test_rejects_changed_signature() -> None:
    report = copy.deepcopy(report_fixture())
    report["public_transcript"]["observations"][3]["signature"] = b64url(b"invalid")
    with pytest.raises(Exception):
        verify(report)


def test_rejects_changed_prf_digest() -> None:
    report = copy.deepcopy(report_fixture())
    report["public_transcript"]["observations"][1]["prf_output_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="same-salt"):
        verify(report)
