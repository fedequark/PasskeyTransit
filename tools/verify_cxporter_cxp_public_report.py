"""Verify retained public assertions from the pinned cxporter export experiment.

This verifies WebAuthn signatures and synthetic PRF digest bindings. The
archive/decryption controls require rerunning the exporter and importer.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from passkeytransit.model import generate_synthetic_passkey

EXPECTED_COMMIT = "96bab31fdadcfd295542bba86b8ec8bd2355294a"
EXPECTED_ALG = "HPKE-Base-X25519-SHA256-AES256GCM"
EXPECTED_CONTROLS = {
    "zip_jwe_shape", "index_and_document_decrypted",
    "passkey_identity_and_state_preserved", "wrong_recipient_rejected",
    "changed_index_ciphertext_rejected", "changed_document_ciphertext_rejected",
    "software_assertions_verified", "software_prf_verified",
}


def require(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def verify_observation(observation: dict, repeat: int, salt_index: int, role_index: int) -> str:
    credential = generate_synthetic_passkey(20261026, repeat + 1)
    expected_rp = credential.rp_id
    transcript = observation["public_transcript"]
    require(transcript["rp_id"] == expected_rp, "RP ID mismatch")
    spki = decode(transcript["public_key_spki"])
    expected_spki = credential.private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    require(spki == expected_spki, "fixture public key mismatch")
    client_bytes = decode(transcript["client_data_json"])
    client = json.loads(client_bytes)
    challenge = hashlib.sha256(
        f"cxporter:{repeat}:challenge:{2 * salt_index + role_index}".encode()
    ).digest()
    require(client["type"] == "webauthn.get", "ceremony type mismatch")
    require(client["challenge"] == b64url(challenge), "challenge mismatch")
    require(client["origin"] == f"https://{expected_rp}", "origin mismatch")
    auth_data = decode(transcript["authenticator_data"])
    require(len(auth_data) >= 37, "short authenticator data")
    require(auth_data[:32] == hashlib.sha256(expected_rp.encode()).digest(), "RP hash mismatch")
    require(bool(auth_data[32] & 1) and bool(auth_data[32] & 4), "UP/UV flags missing")
    try:
        serialization.load_der_public_key(spki).verify(
            decode(transcript["signature"]),
            auth_data + hashlib.sha256(client_bytes).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as exc:
        raise AssertionError("invalid assertion signature") from exc
    salt = hashlib.sha256(f"cxporter:{repeat}:salt:{salt_index}".encode()).digest()
    seed = hashlib.sha256(f"cxporter:{repeat}:uv".encode()).digest()
    prf = hmac.new(seed, hashlib.sha256(b"WebAuthn PRF\x00" + salt).digest(), hashlib.sha256).digest()
    digest = hashlib.sha256(prf).hexdigest()
    require(observation["prf_sha256"] == digest, "PRF digest mismatch")
    require(observation["signature_verified"] is True, "signature flag mismatch")
    require(observation["uv_flag"] is True, "UV flag mismatch")
    require(observation["prf_matches_cxf_seed"] is True, "PRF flag mismatch")
    return digest


def verify_report(report: dict) -> dict:
    root = Path(__file__).resolve().parents[1]
    require(report["external_commit"] == EXPECTED_COMMIT, "external revision mismatch")
    require(report["adapter_sha256"] == hashlib.sha256(
        (root / "interop/cxporter_cxp_probe/main.go").read_bytes()
    ).hexdigest(), "adapter hash mismatch")
    require(report["status"] == "PASS", "online replay did not pass")
    require(report["draft_response_schema_status"] == "FAIL_REQUIRED_ARCHIVE_OMITTED",
            "draft response finding mismatch")
    require(len(report["runs"]) == 2, "repetition count mismatch")
    count = 0
    for repeat, run in enumerate(report["runs"]):
        require(run["repetition"] == repeat, "repetition index mismatch")
        require(run["jwe_alg"] == EXPECTED_ALG, "JWE algorithm mismatch")
        require(run["response_archive_field_present"] is False, "archive field finding mismatch")
        require(run["index_has_header_documents"] is False, "index shape finding mismatch")
        require(set(run["controls"]) == EXPECTED_CONTROLS and all(run["controls"].values()),
                "online controls incomplete")
        require(len(run["public_observations"]) == 2, "salt count mismatch")
        digests = []
        for salt_index, pair in enumerate(run["public_observations"]):
            source = verify_observation(pair["source"], repeat, salt_index, 0)
            destination = verify_observation(pair["destination"], repeat, salt_index, 1)
            require(source == destination and pair["same_input_prf_equal"] is True,
                    "source/destination PRF mismatch")
            require(pair["source"]["public_transcript"]["public_key_spki"] ==
                    pair["destination"]["public_transcript"]["public_key_spki"],
                    "public key changed")
            digests.append(source)
            count += 2
        require(digests[0] != digests[1], "different salts share PRF digest")
        require(run["signed_assertions_verified"] == run["prf_seed_checks_verified"] == 4,
                "run totals mismatch")
        for name in ("archive_sha256", "response_sha256", "decrypted_item_sha256", "index_sha256"):
            value = run[name]
            require(len(value) == 64 and all(c in "0123456789abcdef" for c in value),
                    f"invalid {name}")
    require(report["signed_assertions_verified"] == report["prf_seed_checks_verified"] == count == 8,
            "report totals mismatch")
    return {"public_signatures_verified": count, "public_prf_digests_verified": count,
            "repetitions": 2, "archive_controls_replay_required": True}


def verify_negative_controls(report: dict) -> None:
    for field, value in (("signature", "AA"), ("prf_sha256", "0" * 64)):
        changed = copy.deepcopy(report)
        target = changed["runs"][0]["public_observations"][0]["source"]
        if field == "signature":
            target["public_transcript"][field] = value
        else:
            target[field] = value
        try:
            verify_report(changed)
        except (AssertionError, ValueError):
            pass
        else:
            raise AssertionError(f"public verifier accepted changed {field}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    result = verify_report(report)
    verify_negative_controls(report)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
