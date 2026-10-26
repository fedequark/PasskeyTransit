"""Cross-implementation Proton CXP passkey/PRF-state preservation probe."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519

from passkeytransit.cxf import assert_valid_passkey_document, build_passkey_document
from passkeytransit.hpke import HpkeError, public_jwk
from passkeytransit.model import generate_synthetic_passkey

from run_proton_cxp_wire import IMPORTER, _open
from run_proton_cxf_prf import call_adapter, verify_round_trip


def _first_passkey(document: dict) -> dict:
    return next(
        credential
        for account in document["accounts"]
        for item in account["items"]
        for credential in item["credentials"]
        if credential.get("type") == "passkey"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("exporter", type=Path)
    parser.add_argument("node", type=Path)
    parser.add_argument("authenticator_adapter", type=Path)
    args = parser.parse_args()
    source = build_passkey_document(
        generate_synthetic_passkey(20261026, 1),
        timestamp=1_700_000_000,
        hmac_with_uv=hashlib.sha256(b"proton-cxp:uv").digest(),
        hmac_without_uv=hashlib.sha256(b"proton-cxp:no-uv").digest(),
    )
    assert_valid_passkey_document(source)
    private_key = x25519.X25519PrivateKey.generate()
    request = json.dumps(
        {
            "version": 0,
            "hpke": [{"mode": "base", "kem": 32, "kdf": 1, "aead": 3, "key": public_jwk(private_key.public_key())}],
            "importer": IMPORTER,
            "credentialTypes": ["passkey"],
        },
        separators=(",", ":"),
    ).encode()
    wrapper = json.dumps({"cxp_request": request.decode(), "cxf": json.dumps(source, separators=(",", ":"))}).encode()
    response = subprocess.run(
        [str(args.exporter.resolve())], input=wrapper, capture_output=True, check=True
    ).stdout
    recovered = _open(private_key, request, response)
    source_credential = _first_passkey(source)
    destination_credential = _first_passkey(recovered["document"])
    controls = {
        "credential_id_preserved": source_credential["credentialId"] == destination_credential["credentialId"],
        "rp_id_preserved": source_credential["rpId"] == destination_credential["rpId"],
        "private_key_preserved": source_credential["key"] == destination_credential["key"],
        "user_handle_preserved": source_credential["userHandle"] == destination_credential["userHandle"],
        "hmac_state_preserved": source_credential["fido2Extensions"]["hmacCredentials"]
        == destination_credential["fido2Extensions"]["hmacCredentials"],
    }
    salts = [hashlib.sha256(f"proton-cxp-salt:{i}".encode()).digest() for i in range(2)]
    challenges = [hashlib.sha256(f"proton-cxp-challenge:{i}".encode()).digest() for i in range(4)]
    authentication = call_adapter(
        args.node, args.authenticator_adapter, recovered["document"], salts, challenges
    )
    verified = verify_round_trip(recovered["document"], authentication, salts, challenges)
    controls["destination_assertions_verified"] = verified["signed_assertions_verified"] == 4
    controls["destination_prf_verified"] = verified["prf_seed_checks_verified"] == 4
    try:
        _open(private_key, request.replace(b'"passkey"', b'"basic-auth"'), response)
    except HpkeError:
        controls["changed_request_rejected"] = True
    else:
        controls["changed_request_rejected"] = False
    report = {
        "scope": "Proton Pass common 2.0.0 CXP direct-HPKE exporter; project CXF source and HPKE importer",
        "external_revision": "69a0927f0fe7071243d6c38e404459a69210fdd4",
        "external_tag_object": "b22db5ca6fef03d0e9467c0305f9af8a2826be35",
        "source_cxf_sha256": hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest(),
        "recovered_cxf_sha256": recovered["plaintext_sha256"],
        "controls": controls,
        "signed_assertions_verified": verified["signed_assertions_verified"],
        "prf_seed_checks_verified": verified["prf_seed_checks_verified"],
        "status": "PASS" if all(controls.values()) else "FAIL",
        "limitations": [
            "Proton library import/export and software authenticator, not app vault storage",
            "no ZIP/JWE",
            "no deployed RP assertion",
        ],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
