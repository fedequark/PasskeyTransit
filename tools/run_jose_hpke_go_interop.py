"""Bidirectional JWE HPKE-3-KE test against independently maintained jwx/v4.

The report deliberately omits the ephemeral private key, plaintext, and JWE.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from passkeytransit.cxf import build_passkey_document  # noqa: E402
from passkeytransit.jose_hpke_ke import JoseHpkeError, open_compact, seal_compact  # noqa: E402
from passkeytransit.model import b64url, generate_synthetic_passkey, unb64url  # noqa: E402


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def call_go(binary: Path, mode: str, key: bytes, payload: str, *, success: bool) -> dict:
    process = subprocess.run(
        [str(binary)], input=json.dumps({"mode": mode, "key": b64url(key), "payload": payload}),
        text=True, capture_output=True, timeout=30, check=False,
    )
    result = json.loads(process.stdout)
    if (process.returncode == 0) != (result.get("status") == "PASS"):
        raise RuntimeError("Go process exit and JSON status differ")
    if success and process.returncode:
        raise RuntimeError(f"external JWE library failed: {result.get('error')}")
    return result


def run(binary: Path, go: Path) -> dict:
    document = build_passkey_document(
        generate_synthetic_passkey(20261026, 3), timestamp=1793018074,
        hmac_with_uv=b"u" * 32, hmac_without_uv=b"n" * 32,
    )
    plaintext = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    private = x25519.X25519PrivateKey.generate()
    private_raw = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    python_jwe = seal_compact(private.public_key(), plaintext)
    recovered = unb64url(call_go(binary, "decrypt", private_raw, python_jwe, success=True)["payload"])
    go_jwe = call_go(binary, "encrypt", public_raw, b64url(plaintext), success=True)["payload"]
    reverse = open_compact(private, go_jwe)

    parts = python_jwe.split(".")
    changed = bytearray(unb64url(parts[3]))
    changed[0] ^= 1
    parts[3] = b64url(bytes(changed))
    tampered = call_go(binary, "decrypt", private_raw, ".".join(parts), success=False)
    other = x25519.X25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    wrong = call_go(binary, "decrypt", other, python_jwe, success=False)
    try:
        open_compact(x25519.X25519PrivateKey.generate(), go_jwe)
    except JoseHpkeError:
        python_wrong_rejected = True
    else:
        python_wrong_rejected = False
    checks = {
        "python_to_external_go_plaintext_equal": recovered == plaintext,
        "external_go_to_python_plaintext_equal": reverse == plaintext,
        "external_go_rejects_modified_ciphertext": tampered.get("status") == "FAIL",
        "external_go_rejects_wrong_recipient": wrong.get("status") == "FAIL",
        "python_rejects_wrong_recipient": python_wrong_rejected,
    }
    if not all(checks.values()):
        raise ValueError(f"JOSE HPKE cross-implementation checks failed: {checks}")
    return {
        "evidence_class": "jose-hpke-3-ke-external-library-cryptographic-interop",
        "jose_draft": "draft-ietf-jose-hpke-encrypt-22",
        "go_library": "github.com/lestrrat-go/jwx/v4@v4.6.0",
        "go_version": subprocess.check_output([str(go), "version"], text=True).strip(),
        "document_sha256": sha(plaintext),
        "source_sha256": {
            "python_jose": sha((ROOT / "src/passkeytransit/jose_hpke_ke.py").read_bytes()),
            "go_adapter": sha((ROOT / "interop/jose_hpke_go/main.go").read_bytes()),
            "go_mod": sha((ROOT / "interop/jose_hpke_go/go.mod").read_bytes()),
            "go_sum": sha((ROOT / "interop/jose_hpke_go/go.sum").read_bytes()),
            "runner": sha(Path(__file__).read_bytes()),
        },
        "checks": checks,
        "all_checks_pass": True,
        "limitations": [
            "JOSE draft -22 is work in progress and library semantics may change",
            "Go library performs JWE cryptography only, not CXP ZIP or provider storage",
            "both directions use a synthetic CXF document; no external provider passkey import",
            "no browser assertion, exporter identity, or durable replay protection",
        ],
    }


if __name__ == "__main__":
    binary = Path(sys.argv[1])
    go = Path(sys.argv[2])
    output = Path(sys.argv[3]) if len(sys.argv) > 3 else ROOT / "experiments/jose_hpke_go_interop/report.json"
    result = run(binary, go)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
