"""Cross cxporter's pinned ZIP/JWE exporter with a project importer and PRF control.

Only synthetic credentials enter the Go subprocess. The retained report has
public WebAuthn transcripts and digests, never the private key or HMAC seeds.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from passkeytransit.cxf import assert_valid_passkey_document, build_passkey_document
from passkeytransit.hpke import _extract_and_expand, _labeled_expand, _labeled_extract
from passkeytransit.model import b64url, generate_synthetic_passkey, unb64url

from run_proton_cxf_prf import call_adapter, verify_round_trip

ROOT = Path(__file__).resolve().parents[1]
VENDOR_COMMIT = "96bab31fdadcfd295542bba86b8ec8bd2355294a"
ALG = "HPKE-Base-X25519-SHA256-AES256GCM"
SUITE = b"HPKE\x00\x20\x00\x01\x00\x02"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _public_raw(key: x25519.X25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _key_and_nonce(private: x25519.X25519PrivateKey, encapsulated: bytes) -> tuple[bytes, bytes]:
    sender = x25519.X25519PublicKey.from_public_bytes(encapsulated)
    recipient = _public_raw(private.public_key())
    shared = _extract_and_expand(private.exchange(sender), encapsulated + recipient)
    psk_id_hash = _labeled_extract(SUITE, b"", b"psk_id_hash", b"")
    info_hash = _labeled_extract(SUITE, b"", b"info_hash", b"")
    context = b"\x00" + psk_id_hash + info_hash
    secret = _labeled_extract(SUITE, shared, b"secret", b"")
    return (
        _labeled_expand(SUITE, secret, b"key", context, 32),
        _labeled_expand(SUITE, secret, b"base_nonce", context, 12),
    )


def _open_jwe(compact: bytes, private: x25519.X25519PrivateKey, sequence: int) -> tuple[dict, bytes]:
    parts = compact.decode("ascii").split(".")
    if len(parts) != 5 or parts[1] != "":
        raise ValueError("cxporter member is not five-part compact JWE")
    header = json.loads(unb64url(parts[0]))
    if header.get("alg") != ALG or header.get("enc") != "A256GCM":
        raise ValueError("unexpected cxporter JWE algorithms")
    epk = header["epk"]
    if epk.get("kty") != "OKP" or epk.get("crv") != "X25519":
        raise ValueError("unexpected cxporter JWE ephemeral key")
    key, base_nonce = _key_and_nonce(private, unb64url(epk["x"]))
    expected_nonce = bytearray(base_nonce)
    sequence_bytes = sequence.to_bytes(8, "big")
    for offset, value in enumerate(sequence_bytes):
        expected_nonce[4 + offset] ^= value
    iv = unb64url(parts[2])
    if iv != bytes(expected_nonce):
        raise ValueError("JWE IV does not match HPKE sequence")
    payload = unb64url(parts[3]) + unb64url(parts[4])
    return header, AESGCM(key).decrypt(iv, payload, parts[0].encode("ascii"))


def _rejected(call) -> bool:
    try:
        call()
    except (InvalidTag, ValueError):
        return True
    return False


def _tamper_ciphertext(compact: bytes) -> bytes:
    parts = compact.decode("ascii").split(".")
    ciphertext = bytearray(unb64url(parts[3]))
    if not ciphertext:
        raise ValueError("empty ciphertext in negative control")
    ciphertext[-1] ^= 1
    parts[3] = b64url(bytes(ciphertext))
    return ".".join(parts).encode("ascii")


def run(binary: Path, node: Path, authenticator: Path, output: Path) -> dict:
    revision = subprocess.check_output(
        ["git", "-C", str(binary.parent / "vendor_cxporter"), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != VENDOR_COMMIT:
        raise ValueError("cxporter source is not at the pinned commit")
    runs = []
    for repetition in range(2):
        source = build_passkey_document(
            generate_synthetic_passkey(20261026, repetition + 1),
            timestamp=1_700_000_000,
            hmac_with_uv=hashlib.sha256(f"cxporter:{repetition}:uv".encode()).digest(),
            hmac_without_uv=hashlib.sha256(f"cxporter:{repetition}:no-uv".encode()).digest(),
        )
        assert_valid_passkey_document(source)
        private = x25519.X25519PrivateKey.generate()
        request = {
            "recipientPublicKey": b64url(_public_raw(private.public_key())),
            "cxf": source,
        }
        exported = subprocess.run(
            [str(binary)], input=json.dumps(request).encode(), capture_output=True,
            timeout=30, check=True,
        ).stdout
        response = json.loads(exported)
        archive = unb64url(response["payload"])
        item_id = source["accounts"][0]["items"][0]["id"]
        index_path = "CXP-Export/index.jwe"
        document_path = f"CXP-Export/documents/{item_id}.jwe"
        with zipfile.ZipFile(io.BytesIO(archive)) as package:
            names = set(package.namelist())
            expected = {"CXP-Export/", "CXP-Export/documents/", index_path, document_path}
            if names != expected or package.testzip() is not None:
                raise ValueError("unexpected cxporter ZIP members")
            if any(package.getinfo(name).compress_type != zipfile.ZIP_DEFLATED
                   for name in (index_path, document_path)):
                raise ValueError("JWE members are not DEFLATE compressed")
            index_jwe = package.read(index_path)
            document_jwe = package.read(document_path)

        index_header, index_plaintext = _open_jwe(index_jwe, private, 0)
        document_header, document_plaintext = _open_jwe(document_jwe, private, 1)
        index = json.loads(index_plaintext)
        item = json.loads(document_plaintext)
        original_item = source["accounts"][0]["items"][0]
        if index["accounts"][0]["items"][0]["id"] != item["id"]:
            raise ValueError("index and decrypted document refer to different items")
        recovered = copy.deepcopy(source)
        recovered["accounts"][0]["items"][0] = item
        assert_valid_passkey_document(recovered)
        source_credential = original_item["credentials"][0]
        recovered_credential = item["credentials"][0]
        controls = {
            "zip_jwe_shape": names == expected,
            "index_and_document_decrypted": bool(index_plaintext and document_plaintext),
            "passkey_identity_and_state_preserved": all(
                source_credential[field] == recovered_credential[field]
                for field in ("credentialId", "rpId", "key", "userHandle", "fido2Extensions")
            ),
            "wrong_recipient_rejected": _rejected(
                lambda: _open_jwe(index_jwe, x25519.X25519PrivateKey.generate(), 0)
            ),
            "changed_index_ciphertext_rejected": _rejected(
                lambda: _open_jwe(_tamper_ciphertext(index_jwe), private, 0)
            ),
            "changed_document_ciphertext_rejected": _rejected(
                lambda: _open_jwe(_tamper_ciphertext(document_jwe), private, 1)
            ),
        }
        salts = [hashlib.sha256(f"cxporter:{repetition}:salt:{i}".encode()).digest()
                 for i in range(2)]
        challenges = [hashlib.sha256(f"cxporter:{repetition}:challenge:{i}".encode()).digest()
                      for i in range(4)]
        authentication = call_adapter(node, authenticator, recovered, salts, challenges)
        verified = verify_round_trip(recovered, authentication, salts, challenges)
        controls["software_assertions_verified"] = verified["signed_assertions_verified"] == 4
        controls["software_prf_verified"] = verified["prf_seed_checks_verified"] == 4
        runs.append({
            "repetition": repetition,
            "archive_sha256": _sha(archive),
            "response_sha256": _sha(exported),
            "decrypted_item_sha256": _sha(document_plaintext),
            "index_sha256": _sha(index_plaintext),
            "jwe_alg": index_header["alg"],
            "same_ephemeral_key_across_members": (
                index_header["epk"]["x"] == document_header["epk"]["x"]
            ),
            "response_archive_field_present": "archive" in response,
            "controls": controls,
            "signed_assertions_verified": verified["signed_assertions_verified"],
            "prf_seed_checks_verified": verified["prf_seed_checks_verified"],
            "public_observations": verified["observations"],
        })
    if not all(all(run["controls"].values()) for run in runs):
        raise ValueError("one or more cross-implementation controls failed")
    report = {
        "classification": "external open ZIP/JWE exporter to project importer; software authenticator follow-up",
        "external_commit": VENDOR_COMMIT,
        "adapter_sha256": _sha((ROOT / "interop/cxporter_cxp_probe/main.go").read_bytes()),
        "runs": runs,
        "signed_assertions_verified": sum(run["signed_assertions_verified"] for run in runs),
        "prf_seed_checks_verified": sum(run["prf_seed_checks_verified"] for run in runs),
        "status": "PASS",
        "draft_response_schema_status": "FAIL_REQUIRED_ARCHIVE_OMITTED",
        "limitations": [
            "cxporter is a CLI exporter, not an installed passkey provider app or persistent destination vault",
            "its ExportResponse omits the draft-required archive field",
            "its HPKE-Base-X25519-SHA256-AES256GCM JWE algorithm is not the JOSE HPKE-3-KE profile tested elsewhere",
            "the importer and CXF source document are project-authored; no second provider imports this ZIP",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--authenticator", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(run(arguments.binary.resolve(), arguments.node.resolve(),
                         arguments.authenticator.resolve(), arguments.output.resolve()),
                     indent=2, sort_keys=True))
