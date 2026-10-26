"""Python CXP direct-HPKE exporter to pinned Proton Pass common importer."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from passkeytransit.cxf import assert_valid_passkey_document, build_passkey_document
from passkeytransit.hpke import public_key_from_jwk
from passkeytransit.hpke_chacha import seal_base
from passkeytransit.model import b64url, generate_synthetic_passkey


def _exchange(executable: Path, document: dict, *, corrupt: bool = False) -> tuple[bool, dict | None]:
    process = subprocess.Popen(
        [str(executable.resolve()), "--import"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None and process.stdin is not None
    request = process.stdout.readline().rstrip(b"\r\n")
    if not request:
        raise RuntimeError("Proton importer emitted no CXP request")
    parsed = json.loads(request)
    suite = parsed["hpke"][0]
    if parsed["version"] != 0 or suite["mode"] != "base" or (suite["kem"], suite["kdf"], suite["aead"]) != (32, 1, 3):
        raise ValueError("unsupported Proton CXP request suite")
    enc, ciphertext = seal_base(
        public_key_from_jwk(suite["key"]),
        json.dumps(document, separators=(",", ":")).encode(),
        info=parsed["importer"].encode(),
        aad=request,
    )
    if corrupt:
        ciphertext = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
    response = {
        "version": 0,
        "hpke": {"mode": "base", "kem": 32, "kdf": 1, "aead": 3,
                 "key": public_jwk_from_bytes(enc)},
        "exporter": "PasskeyTransit synthetic exporter",
        "payload": b64url(ciphertext),
    }
    output, errors = process.communicate(json.dumps(response, separators=(",", ":")).encode(), timeout=30)
    if corrupt:
        return process.returncode != 0, None
    if process.returncode != 0:
        raise RuntimeError(f"Proton importer failed: {errors.decode(errors='replace')[-500:]}")
    summary = json.loads(output.decode().strip())
    return True, summary


def public_jwk_from_bytes(raw: bytes) -> dict[str, str]:
    return {"kty": "OKP", "crv": "X25519", "x": b64url(raw)}


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
    parser.add_argument("importer", type=Path)
    args = parser.parse_args()
    source = build_passkey_document(
        generate_synthetic_passkey(20261026, 2),
        timestamp=1_700_000_000,
        hmac_with_uv=hashlib.sha256(b"proton-cxp-reverse:uv").digest(),
        hmac_without_uv=hashlib.sha256(b"proton-cxp-reverse:no-uv").digest(),
    )
    assert_valid_passkey_document(source)
    accepted, summary = _exchange(args.importer, source)
    rejected, _ = _exchange(args.importer, source, corrupt=True)
    destination = json.loads(summary["exported_cxf"]) if summary is not None else {}
    source_key = _first_passkey(source)
    destination_key = _first_passkey(destination)
    controls = {
        "proton_imported_synthetic_passkey": accepted and summary is not None and summary["passkey_count"] == 1,
        "no_import_warnings": summary is not None and summary["warning_count"] == 0,
        "no_export_warnings": summary is not None and summary["export_warning_count"] == 0,
        "credential_id_preserved": source_key["credentialId"] == destination_key["credentialId"],
        "private_key_preserved": source_key["key"] == destination_key["key"],
        "hmac_state_preserved": source_key["fido2Extensions"]["hmacCredentials"]
        == destination_key["fido2Extensions"]["hmacCredentials"],
        "tampered_ciphertext_rejected": rejected,
    }
    report = {
        "scope": "project direct-HPKE CXP exporter to Proton Pass common 2.0.0 importer; synthetic passkey",
        "external_revision": "69a0927f0fe7071243d6c38e404459a69210fdd4",
        "external_tag_object": "b22db5ca6fef03d0e9467c0305f9af8a2826be35",
        "source_cxf_sha256": hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest(),
        "reexported_cxf_sha256": hashlib.sha256(summary["exported_cxf"].encode()).hexdigest(),
        "controls": controls,
        "status": "PASS" if all(controls.values()) else "FAIL",
        "limitations": ["Proton library import, not app vault persistence", "no ZIP/JWE", "no deployed RP assertion"],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
