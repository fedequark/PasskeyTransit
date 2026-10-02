"""Recompute public Phase 17 signature and PRF-digest evidence.

The report intentionally omits CXF, signing keys, HMAC seeds, and raw PRF
outputs. These synthetic fixture values are reproducible from fixed labels.
This verifier cannot attest to Proton's private in-process state or to the
unpublished raw CXF bytes; rerunning the experiment tests those observations.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def fixture_public_key(repeat: int) -> bytes:
    root = hashlib.sha512(f"passkeytransit:20261002:{repeat}".encode()).digest()
    scalar = (int.from_bytes(root[:32], "big") % (P256_ORDER - 1)) + 1
    public = ec.derive_private_key(scalar, ec.SECP256R1()).public_key()
    return public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def expected_prf_digest(repeat: int, salt: bytes, changed_seed: bool) -> str:
    label = "changed-uv" if changed_seed else "uv"
    seed = hashlib.sha256(f"proton-phase17:{repeat - 1}:{label}".encode()).digest()
    prf_input = hashlib.sha256(b"WebAuthn PRF\x00" + salt).digest()
    return hashlib.sha256(hmac.new(seed, prf_input, hashlib.sha256).digest()).hexdigest()


def verify_observation(observation: dict, repeat: int, salt: bytes, challenge: bytes, changed_seed: bool) -> str:
    public = observation["public_transcript"]
    expected_rp = f"rp-{repeat % 5}.example.test"
    require(public["rp_id"] == expected_rp, "wrong RP ID")
    public_spki = unb64url(public["public_key_spki"])
    require(public_spki == fixture_public_key(repeat), "wrong fixture public key")
    client_data = unb64url(public["client_data_json"])
    client = json.loads(client_data)
    require(client["type"] == "webauthn.get", "wrong ceremony type")
    require(client["challenge"] == b64url(challenge), "wrong challenge")
    require(client["origin"] == f"https://{expected_rp}", "wrong origin")
    auth_data = unb64url(public["authenticator_data"])
    require(len(auth_data) >= 37, "short authenticator data")
    require(auth_data[:32] == hashlib.sha256(expected_rp.encode()).digest(), "wrong RP hash")
    require(bool(auth_data[32] & 0x01), "UP flag absent")
    require(bool(auth_data[32] & 0x04), "UV flag absent")
    signature = unb64url(public["signature"])
    key = serialization.load_der_public_key(public_spki)
    try:
        key.verify(signature, auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise AssertionError("invalid WebAuthn signature") from exc
    expected_digest = expected_prf_digest(repeat, salt, changed_seed)
    require(observation["prf_sha256"] == expected_digest, "wrong PRF digest")
    require(observation["signature_verified"] is True, "inconsistent signature flag")
    require(observation["uv_flag"] is True, "inconsistent UV flag")
    require(observation["prf_matches_cxf_seed"] is True, "inconsistent PRF flag")
    return expected_digest


def verify_report(report: dict) -> dict:
    require(report["experiment"] == "phase17-proton-cxf-prf-software", "wrong experiment")
    require(report["proton_package"] == "@protontech/pass-rust-core@2.0.0", "wrong package")
    require(report["repetitions"] == 2 and len(report["runs"]) == 2, "wrong repetition count")
    positive_assertions = control_assertions = 0
    for repeat, run in enumerate(report["runs"], start=1):
        require(run["repeat"] == repeat, "wrong repetition index")
        positive = run["positive"]
        require(len(positive["observations"]) == 2, "wrong positive salt count")
        positive_digests = []
        for salt_index, pair in enumerate(positive["observations"]):
            salt = hashlib.sha256(f"proton-phase17:{repeat - 1}:salt:{salt_index}".encode()).digest()
            digests = []
            for role_index, role in enumerate(("source", "destination")):
                challenge = hashlib.sha256(
                    f"proton-phase17:{repeat - 1}:challenge:{2 * salt_index + role_index}".encode()
                ).digest()
                digests.append(verify_observation(pair[role], repeat, salt, challenge, False))
                positive_assertions += 1
            require(digests[0] == digests[1] and pair["same_input_prf_equal"] is True,
                    "source and destination PRF differ")
            positive_digests.append(digests[0])
        require(positive_digests[0] != positive_digests[1], "different salts have equal PRF digests")
        require(positive["signed_assertions_verified"] == 4 and positive["prf_seed_checks_verified"] == 4,
                "wrong positive counters")

        control = run["changed_seed_control"]
        require(len(control["observations"]) == 1, "wrong control salt count")
        salt = hashlib.sha256(f"proton-phase17:{repeat - 1}:salt:0".encode()).digest()
        pair = control["observations"][0]
        digests = []
        for role_index, role in enumerate(("source", "destination")):
            challenge = hashlib.sha256(f"proton-phase17:{repeat - 1}:control:{role_index}".encode()).digest()
            digests.append(verify_observation(pair[role], repeat, salt, challenge, True))
            control_assertions += 1
        require(digests[0] == digests[1] and pair["same_input_prf_equal"] is True,
                "control source and destination PRF differ")
        require(digests[0] != positive_digests[0] and control["prf_changed"] is True,
                "changed seed did not change PRF")
        require(control["signed_assertions_verified"] == 2 and control["prf_seed_checks_verified"] == 2,
                "wrong control counters")
        require(run["verifier_negative_controls"] == {
            "tampered_signature_rejected": True, "tampered_prf_rejected": True,
        }, "wrong online verifier-control flags")

    require(report["positive_signed_assertions_verified"] == positive_assertions == 8,
            "wrong positive total")
    require(report["positive_prf_seed_checks_verified"] == positive_assertions, "wrong positive PRF total")
    require(report["changed_seed_control_signed_assertions_verified"] == control_assertions == 4,
            "wrong control total")
    require(report["signed_assertions_verified"] == positive_assertions + control_assertions == 12,
            "wrong signature total")
    require(report["prf_seed_checks_verified"] == positive_assertions + control_assertions,
            "wrong PRF total")
    require(report["tampered_signature_rejected"] == report["tampered_prf_rejected"] == 2,
            "wrong online negative-control totals")
    require(report["no_uv_ceremony_evaluated"] is False, "incorrect no-UV claim")
    return {"public_signatures_verified": 12, "public_prf_digests_verified": 12,
            "repetitions": 2}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    print(json.dumps(verify_report(report), sort_keys=True))


if __name__ == "__main__":
    main()
