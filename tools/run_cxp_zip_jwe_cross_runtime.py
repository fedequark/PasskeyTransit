"""Check Python ZIP/JWE export against a separately written Node importer."""

from __future__ import annotations

import hashlib
import json
import base64
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tools")]

from passkeytransit.cxf import build_passkey_document  # noqa: E402
from passkeytransit.cxp import create_import_session  # noqa: E402
from passkeytransit.cxp_zip_jwe_profile import PROFILE, export_zip_jwe  # noqa: E402
from passkeytransit.hpke import public_jwk  # noqa: E402
from passkeytransit.model import b64url, generate_synthetic_passkey  # noqa: E402
from run_cxp_zip_jwe_profile import altered_member  # noqa: E402

NODE = Path("C:/Program Files/nodejs/node.exe") if sys.platform == "win32" else Path("/usr/bin/node")
SCRIPT = ROOT / "interop/node_cxp_zip_jwe.mjs"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def call_node(node: Path, payload: dict, *, expect_success: bool) -> dict:
    completed = subprocess.run(
        [str(node), str(SCRIPT)], input=json.dumps(payload), text=True,
        capture_output=True, timeout=30, check=False,
    )
    result = json.loads(completed.stdout)
    if (completed.returncode == 0) != (result.get("status") == "PASS"):
        raise RuntimeError("Node process status and JSON status disagree")
    if expect_success and completed.returncode:
        raise RuntimeError(f"Node import failed: {result.get('error')}")
    return result


def run(node: Path) -> dict:
    document = build_passkey_document(
        generate_synthetic_passkey(20261026, 2), timestamp=1793018074,
        hmac_with_uv=b"u" * 32, hmac_without_uv=b"n" * 32,
    )
    session = create_import_session("importer.example.test")
    response = export_zip_jwe(session.request, document, exporter="exporter.example.test")
    raw_private = session.private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    private_jwk = {**public_jwk(session.private_key.public_key()), "d": b64url(raw_private)}
    payload = {
        "request": session.request, "privateJwk": private_jwk, "response": response,
        "expectedExporter": "exporter.example.test",
    }
    recovered = call_node(node, payload, expect_success=True)["document"]
    mutated = json.loads(json.dumps(payload))
    mutated["response"] = altered_member(response, "CXP-Export/index.jwe", 3)
    tampered = call_node(node, mutated, expect_success=False)
    central = json.loads(json.dumps(payload))
    archive = bytearray(base64.urlsafe_b64decode(central["response"]["payload"] + "=="))
    central_header = archive.find(b"PK\x01\x02")
    if central_header < 0:
        raise RuntimeError("ZIP central header missing")
    archive[central_header + 16] ^= 1
    central["response"]["payload"] = b64url(bytes(archive))
    central_tampered = call_node(node, central, expect_success=False)
    wrong_key = json.loads(json.dumps(payload))
    another = create_import_session("importer.example.test")
    another_raw = another.private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    wrong_key["privateJwk"] = {**public_jwk(another.private_key.public_key()), "d": b64url(another_raw)}
    wrong = call_node(node, wrong_key, expect_success=False)
    checks = {
        "python_zip_jwe_export_node_import_equal": recovered == document,
        "node_rejects_modified_index_jwe_ciphertext": tampered.get("status") == "FAIL",
        "node_rejects_modified_zip_central_crc": central_tampered.get("status") == "FAIL",
        "node_rejects_wrong_recipient_key": wrong.get("status") == "FAIL",
    }
    if not all(checks.values()):
        raise ValueError(f"cross-runtime ZIP/JWE check failed: {checks}")
    return {
        "evidence_class": "project-authored-cross-runtime-experimental-cxp-zip-jwe",
        "profile": PROFILE,
        "node_version": subprocess.check_output([str(node), "--version"], text=True).strip(),
        "source_sha256": {
            "node_importer": sha(SCRIPT.read_bytes()),
            "python_exporter": sha((ROOT / "src/passkeytransit/cxp_zip_jwe_profile.py").read_bytes()),
            "runner": sha(Path(__file__).read_bytes()),
        },
        "document_sha256": sha(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()),
        "checks": checks,
        "all_checks_pass": True,
        "limitations": [
            "both implementations belong to this project; no external provider CXP exchange",
            "private experimental JOSE key-management algorithm",
            "Node importer checks this two-member ZIP subset, not general ZIP validity or provider state",
            "no browser or mobile credential-provider execution",
        ],
    }


if __name__ == "__main__":
    node = Path(sys.argv[1]) if len(sys.argv) > 1 else NODE
    output = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "experiments/cxp_zip_jwe_experimental/cross_runtime.json"
    result = run(node)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
