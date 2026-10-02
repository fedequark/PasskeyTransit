from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
from pathlib import Path
from typing import Any

from .campaign import build_c1_corpus
from .cxf import assert_valid_passkey_document, extract_first_passkey
from .cxp import ReplayCache, create_import_session, export_cxf, import_cxf
from .model import b64url, unb64url


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _software_prf(document: dict[str, Any], salt: bytes, *, user_verified: bool) -> bytes:
    state = extract_first_passkey(document)["fido2Extensions"]["hmacCredentials"]
    if state["algorithm"] != "hmac-sha256":
        raise ValueError("unsupported CXF HMAC algorithm")
    secret = unb64url(state["credWithUV" if user_verified else "credWithoutUV"])
    prf_input = hashlib.sha256(b"WebAuthn PRF\x00" + salt).digest()
    return hmac.new(secret, prf_input, hashlib.sha256).digest()


def _node_call(node: Path, script: Path, request: dict[str, Any], *, expect_success: bool = True) -> dict[str, Any]:
    completed = subprocess.run(
        [str(node), str(script)], input=json.dumps(request), text=True,
        capture_output=True, check=False, timeout=30,
    )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Node CXP implementation emitted invalid JSON: {completed.stderr.strip()}") from exc
    if not isinstance(result, dict) or (completed.returncode == 0) != (result.get("status") == "PASS"):
        raise RuntimeError("Node CXP implementation returned an inconsistent status")
    if expect_success and completed.returncode != 0:
        raise RuntimeError(f"Node CXP implementation failed: {result.get('error')}")
    return result


def run_cross_runtime_cxp(protocol_path: Path, node: Path, script: Path, output: Path) -> dict[str, Any]:
    """Exercise both directions of the experimental CXP binding across runtimes.

    The Node implementation is separately written but belongs to this project.
    It is not an external provider or a claim of normative CXP interoperability.
    """
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    document = build_c1_corpus(protocol)[6 * 32][2]
    assert_valid_passkey_document(document)
    source_hash = hashlib.sha256(_canonical(document)).hexdigest()

    # Node exporter -> Python importer.
    python_session = create_import_session("importer.example.test")
    node_response = _node_call(node, script, {
        "operation": "export", "request": python_session.request,
        "document": document, "exporter": "exporter.example.test",
    })["response"]
    python_recovered = import_cxf(
        python_session, node_response, expected_exporter="exporter.example.test", replay_cache=ReplayCache()
    )
    assert_valid_passkey_document(python_recovered)

    # Python exporter -> Node importer.
    node_session = _node_call(node, script, {"operation": "initiate", "importer": "importer.example.test"})
    python_response = export_cxf(node_session["request"], document, exporter="exporter.example.test")
    node_recovered = _node_call(node, script, {
        "operation": "import", "request": node_session["request"],
        "privateJwk": node_session["privateJwk"], "response": python_response,
        "expectedExporter": "exporter.example.test",
    })["document"]
    assert_valid_passkey_document(node_recovered)

    # The second importer must reject ciphertext manipulation.
    mutated = json.loads(json.dumps(python_response))
    payload = mutated["payload"]
    mutated["payload"] = ("A" if payload[0] != "A" else "B") + payload[1:]
    tampered = _node_call(node, script, {
        "operation": "import", "request": node_session["request"],
        "privateJwk": node_session["privateJwk"], "response": mutated,
        "expectedExporter": "exporter.example.test",
    }, expect_success=False)

    # Execute the CXF HMAC state after transport. This software control uses
    # WebAuthn's PRF salt mapping but is not a browser/CTAP ceremony.
    salt = hashlib.sha256(b"passkeytransit-phase14-software-prf-salt").digest()
    prf_checks: dict[str, bool] = {}
    for user_verified, label in ((True, "with_uv"), (False, "without_uv")):
        original = _software_prf(document, salt, user_verified=user_verified)
        node_values = [
            _node_call(node, script, {
                "operation": "eval-prf", "document": candidate,
                "salt": b64url(salt), "userVerified": user_verified,
            })["prfFirst"]
            for candidate in (document, python_recovered, node_recovered)
        ]
        prf_checks[f"software_prf_{label}_preserved"] = (
            all(unb64url(value) == original for value in node_values)
            and _software_prf(python_recovered, salt, user_verified=user_verified) == original
            and _software_prf(node_recovered, salt, user_verified=user_verified) == original
        )
    without_prf = json.loads(json.dumps(node_recovered))
    without_prf["accounts"][0]["items"][0]["credentials"][0]["fido2Extensions"].pop("hmacCredentials")
    missing_prf = _node_call(node, script, {
        "operation": "eval-prf", "document": without_prf,
        "salt": b64url(salt), "userVerified": True,
    }, expect_success=False)

    checks = {
        "node_export_python_import_equal": _canonical(python_recovered) == _canonical(document),
        "python_export_node_import_equal": _canonical(node_recovered) == _canonical(document),
        "node_rejects_modified_ciphertext": tampered.get("status") == "FAIL",
        **prf_checks,
        "software_prf_missing_state_rejected": missing_prf.get("status") == "FAIL",
    }
    result = {
        "evidence_class": "cross-runtime-experimental-cxp-exchange",
        "source_corpus_protocol_id": protocol["protocol_id"],
        "study_status": "post-inspection-exploratory",
        "protocol_sha256": hashlib.sha256(protocol_path.read_bytes()).hexdigest(),
        "node_script_sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
        "python_runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "node_version": subprocess.check_output([str(node), "--version"], text=True).strip(),
        "implementations": ["passkeytransit Python reference", "project-authored standalone Node.js"],
        "document_sha256": source_hash,
        "checks": checks,
        "all_checks_pass": all(checks.values()),
        "limitations": [
            "the Node implementation is project-authored, not a third-party provider",
            "the tested single-document binding is experimental and omits normative CXP ZIP/JWE mapping",
            "this exchange does not establish browser PRF preservation or durable provider storage",
            "software PRF evaluation is not a browser or CTAP authenticator ceremony",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"cross-runtime output is immutable: {output}")
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result
