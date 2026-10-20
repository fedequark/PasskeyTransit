"""Independently verify the public WebAuthn assertions in a Phase 14 report."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def decode(value: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify(report: dict) -> dict[str, object]:
    transcript = report["public_transcript"]
    require(transcript["schema_version"] == 1, "unexpected transcript version")
    require(transcript["rp_id"] == report["rp_id"] == "localhost", "RP ID mismatch")
    credential_id = decode(transcript["credential_id"])
    require(hashlib.sha256(credential_id).hexdigest() == report["credential_id_sha256"], "credential ID hash mismatch")
    public_key = serialization.load_der_public_key(decode(transcript["public_key_spki"]))
    require(isinstance(public_key, ec.EllipticCurvePublicKey), "expected an EC public key")
    observations = transcript["observations"]
    require(isinstance(observations, list) and len(observations) == 4, "expected four assertions")
    require([o["stage"] for o in observations] == [
        "source_initial", "source_repeat", "source_other_salt", "destination"
    ], "unexpected assertion stages")
    seen_challenges: set[bytes] = set()
    digests: list[str | None] = []
    salts: list[bytes] = []
    for index, observation in enumerate(observations):
        require(set(observation) == {
            "stage", "challenge", "salt", "raw_id", "authenticator_data",
            "client_data_json", "signature", "prf_present", "prf_output_sha256"
        }, f"unexpected fields in assertion {index}")
        challenge = decode(observation["challenge"])
        require(len(challenge) == 32 and challenge not in seen_challenges, f"bad challenge {index}")
        seen_challenges.add(challenge)
        salt = decode(observation["salt"])
        require(len(salt) == 32, f"bad salt {index}")
        salts.append(salt)
        require(decode(observation["raw_id"]) == credential_id, f"credential ID changed {index}")
        auth_data = decode(observation["authenticator_data"])
        client_data_bytes = decode(observation["client_data_json"])
        require(len(auth_data) >= 37, f"short authenticator data {index}")
        require(auth_data[:32] == hashlib.sha256(b"localhost").digest(), f"RP hash mismatch {index}")
        require(auth_data[32] & 0x05 == 0x05, f"UP or UV missing {index}")
        client_data = json.loads(client_data_bytes)
        require(client_data["type"] == "webauthn.get", f"wrong ceremony type {index}")
        require(decode(client_data["challenge"]) == challenge, f"challenge mismatch {index}")
        origin = urlparse(client_data["origin"])
        require(origin.scheme == "http" and origin.hostname == "localhost" and origin.port is not None,
                f"unexpected origin {index}")
        signed = auth_data + hashlib.sha256(client_data_bytes).digest()
        public_key.verify(decode(observation["signature"]), signed, ec.ECDSA(hashes.SHA256()))
        digest = observation["prf_output_sha256"]
        require(observation["prf_present"] is (digest is not None), f"PRF presence mismatch {index}")
        require(digest is None or (isinstance(digest, str) and len(digest) == 64 and
                all(c in "0123456789abcdef" for c in digest)), f"bad PRF digest {index}")
        digests.append(digest)
    require(salts[0] == salts[1] == salts[3] and salts[2] != salts[0], "salt control mismatch")
    require(digests[0] is not None and digests[0] == digests[1], "same-salt PRF mismatch")
    require(digests[2] is not None and digests[2] != digests[0], "other-salt PRF did not change")
    require(digests[3] is None, "destination PRF must be absent")
    require(report["source_prf_output_sha256"] == digests[0], "source PRF digest mismatch")
    checks = report["checks"]
    for name in ("all_assertion_signatures_valid", "credential_id_preserved", "source_prf_executed",
                 "same_salt_stable", "different_salt_changes_output", "destination_prf_result_missing"):
        require(checks[name] is True, f"runner check disagrees: {name}")
    require(report["all_checks_pass"] is True, "runner did not pass")
    return {"signed_assertions_verified": 4, "prf_digest_bindings_verified": 4,
            "distinct_challenges": 4, "raw_prf_outputs_retained": 0}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.report.read_text(encoding="utf-8"))), sort_keys=True))


if __name__ == "__main__":
    main()
