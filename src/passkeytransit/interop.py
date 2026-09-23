from __future__ import annotations

import hashlib
import json
import subprocess
from importlib.metadata import version
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.hpke import (
    AEAD,
    KDF,
    KEM,
    MLKEM768X25519PrivateKey,
    Suite,
)

from .cxf import build_passkey_document
from .hpke import open_base, seal_base
from .model import generate_synthetic_passkey


def run_independent_interop(node_path: Path, node_verifier: Path, output_path: Path) -> dict[str, Any]:
    if not node_path.is_file():
        raise FileNotFoundError(node_path)
    if not node_verifier.is_file():
        raise FileNotFoundError(node_verifier)
    info = b"PasskeyTransit phase-8 independent HPKE interop"
    plaintext = b"independent implementation boundary"
    recipient = x25519.X25519PrivateKey.generate()
    native_suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

    native_message = native_suite.encrypt(plaintext, recipient.public_key(), info)
    native_enc, native_ciphertext = native_message[:32], native_message[32:]
    native_to_reference = open_base(
        recipient, native_enc, native_ciphertext, info=info, aad=b""
    ) == plaintext

    reference_enc, reference_ciphertext = seal_base(
        recipient.public_key(), plaintext, info=info, aad=b""
    )
    reference_to_native = native_suite.decrypt(
        reference_enc + reference_ciphertext, recipient, info
    ) == plaintext

    hybrid_private = MLKEM768X25519PrivateKey(
        mlkem.MLKEM768PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    )
    hybrid_suite = Suite(KEM.MLKEM768_X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
    hybrid_message = hybrid_suite.encrypt(plaintext, hybrid_private.public_key(), info)
    hybrid_round_trip = hybrid_suite.decrypt(hybrid_message, hybrid_private, info) == plaintext

    credential = generate_synthetic_passkey(20260912, 6)
    document = build_passkey_document(credential, timestamp=1789167600)
    node = subprocess.run(
        [str(node_path), str(node_verifier)],
        input=json.dumps(document),
        text=True,
        capture_output=True,
        check=True,
        timeout=30,
    )
    node_result = json.loads(node.stdout)
    public_hash = hashlib.sha256(credential.public_key_spki).hexdigest()
    node_cxf_verified = (
        node_result["envelope"]
        and node_result["passkeyType"]
        and node_result["pkcs8Parsed"]
        and node_result["publicSpkiSha256"] == public_hash
        and node_result["credentialIdSha256"] == hashlib.sha256(credential.credential_id).hexdigest()
        and node_result["largeBlobSha256"] == hashlib.sha256(credential.large_blob or b"").hexdigest()
    )
    node_version = subprocess.check_output([str(node_path), "--version"], text=True).strip()
    project_root = node_verifier.resolve().parent.parent
    try:
        source_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=project_root, text=True).strip()
        unstaged = subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=project_root).returncode
        staged = subprocess.run(["git", "diff", "--cached", "--quiet", "HEAD", "--"], cwd=project_root).returncode
        source_dirty = unstaged != 0 or staged != 0
    except Exception:
        source_commit, source_dirty = None, None
    result = {
        "phase": 8,
        "evidence_class": "independent-implementation-interoperability",
        "implementations": {
            "reference_hpke": "passkeytransit.hpke",
            "native_hpke": f"cryptography {version('cryptography')}",
            "independent_cxf_consumer": f"Node.js {node_version}",
        },
        "git": {"source_commit": source_commit, "source_dirty": source_dirty},
        "hpke": {
            "suite": "DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-128-GCM",
            "native_to_reference": native_to_reference,
            "reference_to_native": reference_to_native,
            "aad_profile_interop": "NOT_EVALUATED_NATIVE_API_HAS_NO_AAD_PARAMETER",
        },
        "cxf_node_consumer": {"verified": node_cxf_verified, **node_result},
        "pqc_exploration": {
            "suite": "ML-KEM-768+X25519/HKDF-SHA256/AES-128-GCM",
            "round_trip": hybrid_round_trip,
            "encapsulation_bytes": KEM.MLKEM768_X25519.enc_length(),
            "message_bytes": len(hybrid_message),
            "cxp_normative_assessment": "OUT_OF_SCOPE",
        },
        "all_applicable_checks_pass": native_to_reference and reference_to_native and node_cxf_verified and hybrid_round_trip,
        "limitations": [
            "independent HPKE check covers the RFC 9180 base suite, not the underspecified full CXP ZIP/JWE framing",
            "cryptography's single-shot native HPKE API does not expose application AAD",
            "the hybrid PQC suite is exploratory and is not claimed as a CXP v0 profile",
        ],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        raise FileExistsError(f"interop output is immutable: {output_path}")
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result
