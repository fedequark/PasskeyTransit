"""Run a synthetic Proton CXP exporter against an independent Python HPKE importer."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519

from passkeytransit.hpke import HpkeError, public_jwk
from passkeytransit.hpke_chacha import open_base
from passkeytransit.model import unb64url

ROOT = Path(__file__).resolve().parents[1]
IMPORTER = "PasskeyTransit synthetic importer"
EXPECTED_EMAIL = "cxp-synthetic@example.test"


def _open(private_key: x25519.X25519PrivateKey, request: bytes, response: bytes) -> dict:
    parsed = json.loads(response)
    if parsed["version"] != 0 or parsed["exporter"] != "Proton Pass synthetic exporter":
        raise ValueError("unexpected CXP response metadata")
    hpke = parsed["hpke"]
    if any(hpke[key] != value for key, value in {"mode": "base", "kem": 32, "kdf": 1, "aead": 3}.items()):
        raise ValueError("unexpected Proton HPKE suite")
    key = hpke["key"]
    if key["kty"] != "OKP" or key["crv"] != "X25519":
        raise ValueError("unexpected encapsulated key type")
    plaintext = open_base(
        private_key,
        unb64url(key["x"]),
        unb64url(parsed["payload"]),
        info=IMPORTER.encode(),
        aad=request,
    )
    document = json.loads(plaintext)
    return {"document": document, "plaintext_sha256": hashlib.sha256(plaintext).hexdigest()}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("exporter", type=Path, help="compiled Proton-backed Rust adapter")
    args = parser.parse_args()
    private_key = x25519.X25519PrivateKey.generate()
    request = json.dumps(
        {
            "version": 0,
            "hpke": [{"mode": "base", "kem": 32, "kdf": 1, "aead": 3, "key": public_jwk(private_key.public_key())}],
            "importer": IMPORTER,
            "credentialTypes": ["basic-auth"],
        },
        separators=(",", ":"),
    ).encode()
    process = subprocess.run([str(args.exporter.resolve())], input=request, capture_output=True, check=True)
    response = process.stdout
    positive = _open(private_key, request, response)
    recovered = json.dumps(positive["document"], separators=(",", ":"))
    controls = {
        "synthetic_cxf_recovered": EXPECTED_EMAIL in recovered and "synthetic-password-1" in recovered,
    }
    for name, changed_request, changed_key in (
        ("altered_request_rejected", request.replace(b"synthetic importer", b"changed importer"), private_key),
        ("wrong_recipient_rejected", request, x25519.X25519PrivateKey.generate()),
    ):
        try:
            _open(changed_key, changed_request, response)
        except HpkeError:
            controls[name] = True
        else:
            controls[name] = False
    tampered = json.loads(response)
    payload = bytearray(unb64url(tampered["payload"]))
    payload[-1] ^= 1
    from passkeytransit.model import b64url

    tampered["payload"] = b64url(bytes(payload))
    try:
        _open(private_key, request, json.dumps(tampered).encode())
    except HpkeError:
        controls["tampered_ciphertext_rejected"] = True
    else:
        controls["tampered_ciphertext_rejected"] = False
    report = {
        "scope": "Proton Pass common 2.0.0 CXP direct HPKE exporter to project Python importer; synthetic basic-auth only",
        "external_revision": "69a0927f0fe7071243d6c38e404459a69210fdd4",
        "external_tag_object": "b22db5ca6fef03d0e9467c0305f9af8a2826be35",
        "request_sha256": hashlib.sha256(request).hexdigest(),
        "response_sha256": hashlib.sha256(response).hexdigest(),
        "plaintext_sha256": positive["plaintext_sha256"],
        "controls": controls,
        "status": "PASS" if all(controls.values()) else "FAIL",
        "limitations": ["no passkey in this fixture", "no provider vault import", "no ZIP/JWE", "no RP assertion"],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
