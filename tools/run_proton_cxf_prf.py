"""Exploratory CXF/PRF run against Proton Pass's pinned, prebuilt WASM module.

Only synthetic credentials are sent to the adapter. Raw CXF and assertions stay
in process memory; the saved report contains counts, booleans, and digests.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import json
import subprocess
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from passkeytransit.cxf import assert_valid_passkey_document, build_passkey_document
from passkeytransit.model import b64url, generate_synthetic_passkey, unb64url


PROTON_VERSION = "2.0.0"
PROTON_SOURCE_COMMIT = "69a0927f0fe7071243d6c38e404459a69210fdd4"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(data: object) -> bytes:
    return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def first_passkey(document: dict) -> dict:
    for account in document["accounts"]:
        for item in account["items"]:
            for credential in item["credentials"]:
                if credential.get("type") == "passkey":
                    return credential
    raise AssertionError("CXF document contains no passkey")


def call_adapter(node: Path, adapter: Path, document: dict, salts: list[bytes], challenges: list[bytes]) -> dict:
    request = {
        "document": json.dumps(document, separators=(",", ":")),
        "origin": f"https://{first_passkey(document)['rpId']}",
        "salts": [b64url(value) for value in salts],
        "challenges": [b64url(value) for value in challenges],
    }
    result = subprocess.run(
        [str(node), "--no-warnings", "--experimental-wasm-modules", str(adapter)],
        input=json.dumps(request), text=True, capture_output=True, timeout=60, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Proton adapter failed; no credential bytes were saved")
    response = json.loads(result.stdout)
    if response.get("version") != PROTON_VERSION:
        raise AssertionError("unexpected Proton module version")
    return response


def expected_prf(seed: bytes, salt: bytes) -> bytes:
    prf_input = hashlib.sha256(b"WebAuthn PRF\x00" + salt).digest()
    return hmac.new(seed, prf_input, hashlib.sha256).digest()


def verify_observation(observation: dict, document: dict, salt: bytes, challenge: bytes) -> dict:
    credential = first_passkey(document)
    client_bytes = unb64url(observation["client_data_json"])
    auth_data = unb64url(observation["authenticator_data"])
    signature = unb64url(observation["signature"])
    client = json.loads(client_bytes)
    assert client["type"] == "webauthn.get"
    assert client["challenge"] == b64url(challenge)
    assert client["origin"] == f"https://{credential['rpId']}"
    assert unb64url(observation["raw_id"]) == unb64url(credential["credentialId"])
    assert auth_data[:32] == hashlib.sha256(credential["rpId"].encode()).digest()
    assert auth_data[32] & 0x01  # user presence
    assert auth_data[32] & 0x04  # required UV ceremony
    private = serialization.load_der_private_key(unb64url(credential["key"]), password=None)
    public = private.public_key()
    try:
        public.verify(signature, auth_data + hashlib.sha256(client_bytes).digest(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise AssertionError("invalid independent WebAuthn signature") from exc
    actual = unb64url(observation["prf_first"])
    seed = unb64url(credential["fido2Extensions"]["hmacCredentials"]["credWithUV"])
    assert len(actual) == 32
    assert actual == expected_prf(seed, salt)
    return {"signature_verified": True, "uv_flag": True, "prf_matches_cxf_seed": True, "prf_sha256": digest(actual)}


def verify_round_trip(document: dict, response: dict, salts: list[bytes], challenges: list[bytes]) -> dict:
    assert response["import_warnings"] == []
    assert response["export_warnings"] == []
    assert response["reimport_warnings"] == []
    exported = json.loads(response["exported_cxf"])
    # Our local validator intentionally accepts a passkey-only CXF profile;
    # Proton also emits a basic-auth credential for the same login item.
    passkey_projection = copy.deepcopy(exported)
    for account in passkey_projection["accounts"]:
        for item in account["items"]:
            item["credentials"] = [c for c in item["credentials"] if c.get("type") == "passkey"]
    assert_valid_passkey_document(passkey_projection)
    source = first_passkey(document)
    destination = first_passkey(exported)
    retained = {
        field: source[field] == destination[field]
        for field in ("credentialId", "rpId", "userHandle", "key")
    }
    for field in ("credWithUV", "credWithoutUV"):
        retained[field] = (
            source["fido2Extensions"]["hmacCredentials"][field]
            == destination["fido2Extensions"]["hmacCredentials"][field]
        )
    assert all(retained.values())
    observations = []
    for index, pair in enumerate(response["observations"]):
        source_result = verify_observation(pair["source"], document, salts[index], challenges[2 * index])
        destination_result = verify_observation(pair["destination"], exported, salts[index], challenges[2 * index + 1])
        assert source_result["prf_sha256"] == destination_result["prf_sha256"]
        observations.append({
            "source": source_result,
            "destination": destination_result,
            "same_input_prf_equal": True,
        })
    assert len(observations) == len(salts)
    if len(salts) > 1:
        assert observations[0]["source"]["prf_sha256"] != observations[1]["source"]["prf_sha256"]
    return {
        "source_cxf_sha256": digest(canonical(document)),
        "exported_cxf_sha256": digest(canonical(exported)),
        "retained": retained,
        "observations": observations,
        "signed_assertions_verified": 2 * len(salts),
        "prf_seed_checks_verified": 2 * len(salts),
    }


def run(node: Path, adapter: Path, output: Path) -> dict:
    runs = []
    for repeat in range(2):
        # Indices 1 and 2 have no largeBlob, isolating the HMAC-state route.
        passkey = generate_synthetic_passkey(20261002, repeat + 1)
        uv_seed = hashlib.sha256(f"proton-phase17:{repeat}:uv".encode()).digest()
        no_uv_seed = hashlib.sha256(f"proton-phase17:{repeat}:no-uv".encode()).digest()
        document = build_passkey_document(
            passkey, timestamp=1790899200, hmac_with_uv=uv_seed, hmac_without_uv=no_uv_seed,
        )
        assert_valid_passkey_document(document)
        salts = [hashlib.sha256(f"proton-phase17:{repeat}:salt:{i}".encode()).digest() for i in range(2)]
        challenges = [hashlib.sha256(f"proton-phase17:{repeat}:challenge:{i}".encode()).digest() for i in range(4)]
        response = call_adapter(node, adapter, document, salts, challenges)
        positive = verify_round_trip(document, response, salts, challenges)

        changed = copy.deepcopy(document)
        changed_seed = hashlib.sha256(f"proton-phase17:{repeat}:changed-uv".encode()).digest()
        first_passkey(changed)["fido2Extensions"]["hmacCredentials"]["credWithUV"] = b64url(changed_seed)
        assert_valid_passkey_document(changed)
        control_challenges = [
            hashlib.sha256(f"proton-phase17:{repeat}:control:{i}".encode()).digest() for i in range(2)
        ]
        control_response = call_adapter(node, adapter, changed, salts[:1], control_challenges)
        control = verify_round_trip(changed, control_response, salts[:1], control_challenges)
        assert positive["observations"][0]["source"]["prf_sha256"] != control["observations"][0]["source"]["prf_sha256"]
        runs.append({
            "repeat": repeat + 1,
            "positive": positive,
            "changed_seed_control": {
                "prf_changed": True,
                "signed_assertions_verified": control["signed_assertions_verified"],
                "prf_seed_checks_verified": control["prf_seed_checks_verified"],
            },
        })

    report = {
        "experiment": "phase17-proton-cxf-prf-software",
        "classification": "source-informed exploratory; software authenticator, no browser/provider-app CXP",
        "proton_package": "@protontech/pass-rust-core@2.0.0",
        "proton_source_commit": PROTON_SOURCE_COMMIT,
        "repetitions": len(runs),
        "positive_signed_assertions_verified": sum(run["positive"]["signed_assertions_verified"] for run in runs),
        "positive_prf_seed_checks_verified": sum(run["positive"]["prf_seed_checks_verified"] for run in runs),
        "changed_seed_control_signed_assertions_verified": sum(
            run["changed_seed_control"]["signed_assertions_verified"] for run in runs
        ),
        "signed_assertions_verified": sum(
            run["positive"]["signed_assertions_verified"] + run["changed_seed_control"]["signed_assertions_verified"]
            for run in runs
        ),
        "prf_seed_checks_verified": sum(
            run["positive"]["prf_seed_checks_verified"] + run["changed_seed_control"]["prf_seed_checks_verified"]
            for run in runs
        ),
        "uv_seed_preserved": True,
        "no_uv_seed_bytes_preserved": True,
        "no_uv_ceremony_evaluated": False,
        "runs": runs,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--adapter", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.node, args.adapter, args.output)
    print(json.dumps({key: result[key] for key in (
        "experiment", "repetitions", "signed_assertions_verified", "prf_seed_checks_verified",
    )}))


if __name__ == "__main__":
    main()
