"""Exploratory CXF/PRF run against Proton Pass's pinned, prebuilt WASM module.

Only synthetic credentials are sent to the adapter. Raw CXF, signing keys,
HMAC seeds, and PRF outputs stay in process memory. The saved report retains
public assertion transcripts, counts, booleans, and digests.
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


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


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
    require(response.get("version") == PROTON_VERSION, "unexpected Proton module version")
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
    require(client["type"] == "webauthn.get", "wrong WebAuthn ceremony type")
    require(client["challenge"] == b64url(challenge), "challenge mismatch")
    require(client["origin"] == f"https://{credential['rpId']}", "origin mismatch")
    require(unb64url(observation["raw_id"]) == unb64url(credential["credentialId"]), "credential ID mismatch")
    require(auth_data[:32] == hashlib.sha256(credential["rpId"].encode()).digest(), "RP hash mismatch")
    require(bool(auth_data[32] & 0x01), "user presence missing")
    require(bool(auth_data[32] & 0x04), "user verification missing")
    private = serialization.load_der_private_key(unb64url(credential["key"]), password=None)
    public = private.public_key()
    try:
        public.verify(signature, auth_data + hashlib.sha256(client_bytes).digest(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise AssertionError("invalid independent WebAuthn signature") from exc
    actual = unb64url(observation["prf_first"])
    seed = unb64url(credential["fido2Extensions"]["hmacCredentials"]["credWithUV"])
    require(len(actual) == 32, "wrong PRF output length")
    require(actual == expected_prf(seed, salt), "PRF output differs from CXF seed calculation")
    return {
        "signature_verified": True,
        "uv_flag": True,
        "prf_matches_cxf_seed": True,
        "prf_sha256": digest(actual),
        "public_transcript": {
            "rp_id": credential["rpId"],
            "public_key_spki": b64url(public.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
            )),
            "client_data_json": observation["client_data_json"],
            "authenticator_data": observation["authenticator_data"],
            "signature": observation["signature"],
        },
    }


def rejects_tampered_observation(observation: dict, document: dict, salt: bytes, challenge: bytes, field: str) -> bool:
    altered = copy.deepcopy(observation)
    value = bytearray(unb64url(altered[field]))
    require(bool(value), f"empty {field} in negative control")
    value[-1] ^= 1
    altered[field] = b64url(bytes(value))
    try:
        verify_observation(altered, document, salt, challenge)
    except AssertionError:
        return True
    raise AssertionError(f"tampered {field} was accepted")


def verify_round_trip(document: dict, response: dict, salts: list[bytes], challenges: list[bytes]) -> dict:
    require(response["import_warnings"] == [], "Proton import warning")
    require(response["export_warnings"] == [], "Proton export warning")
    require(response["reimport_warnings"] == [], "Proton reimport warning")
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
    require(all(retained.values()), "CXF identity, key, or HMAC seed changed")
    observations = []
    for index, pair in enumerate(response["observations"]):
        source_result = verify_observation(pair["source"], document, salts[index], challenges[2 * index])
        destination_result = verify_observation(pair["destination"], exported, salts[index], challenges[2 * index + 1])
        require(source_result["prf_sha256"] == destination_result["prf_sha256"], "source and destination PRF differ")
        observations.append({
            "source": source_result,
            "destination": destination_result,
            "same_input_prf_equal": True,
        })
    require(len(observations) == len(salts), "observation count mismatch")
    if len(salts) > 1:
        require(observations[0]["source"]["prf_sha256"] != observations[1]["source"]["prf_sha256"],
                "different salts produced the same PRF")
    return {
        "source_cxf_sha256": digest(canonical(document)),
        "exported_cxf_sha256": digest(canonical(exported)),
        "retained": retained,
        "observations": observations,
        "signed_assertions_verified": 2 * len(salts),
        "prf_seed_checks_verified": 2 * len(salts),
    }


def run(node: Path, adapter: Path, output: Path) -> dict:
    adapter_root = adapter.resolve().parent
    lockfile = adapter_root / "package-lock.json"
    wasm = adapter_root / "node_modules" / "@protontech" / "pass-rust-core" / "worker" / "proton_pass_web_bg.wasm"
    require(lockfile.is_file(), "pinned Proton npm lockfile missing")
    require(wasm.is_file(), "pinned Proton worker WASM missing")
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
        require(positive["observations"][0]["source"]["prf_sha256"] != control["observations"][0]["source"]["prf_sha256"],
                "changed UV seed did not change PRF")
        negative_controls = {
            "tampered_signature_rejected": rejects_tampered_observation(
                response["observations"][0]["source"], document, salts[0], challenges[0], "signature",
            ),
            "tampered_prf_rejected": rejects_tampered_observation(
                response["observations"][0]["source"], document, salts[0], challenges[0], "prf_first",
            ),
        }
        runs.append({
            "repeat": repeat + 1,
            "positive": positive,
            "verifier_negative_controls": negative_controls,
            "changed_seed_control": {
                "prf_changed": True,
                "signed_assertions_verified": control["signed_assertions_verified"],
                "prf_seed_checks_verified": control["prf_seed_checks_verified"],
                "observations": control["observations"],
            },
        })

    report = {
        "experiment": "phase17-proton-cxf-prf-software",
        "classification": "source-informed exploratory; software authenticator, no browser/provider-app CXP",
        "proton_package": "@protontech/pass-rust-core@2.0.0",
        "proton_source_commit": PROTON_SOURCE_COMMIT,
        "artifact_sha256": {
            "npm_lockfile": digest(lockfile.read_bytes()),
            "proton_worker_wasm": digest(wasm.read_bytes()),
            "node_adapter": digest(adapter.read_bytes()),
            "python_driver": digest(Path(__file__).read_bytes()),
        },
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
        "tampered_signature_rejected": sum(run["verifier_negative_controls"]["tampered_signature_rejected"] for run in runs),
        "tampered_prf_rejected": sum(run["verifier_negative_controls"]["tampered_prf_rejected"] for run in runs),
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
        "tampered_signature_rejected", "tampered_prf_rejected",
    )}))


if __name__ == "__main__":
    main()
