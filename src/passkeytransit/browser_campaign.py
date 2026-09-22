from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import threading
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
from pathlib import Path
from typing import Any, Iterator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from playwright.sync_api import sync_playwright

from . import __version__
from .campaign import (
    ORACLES,
    StrictPreservationError,
    _apply_profile,
    _bootstrap,
    _canonical,
    _classify,
    _evaluate,
    _design_cell_summary,
    _git_state,
    _oracle,
    _paired_route_comparisons,
    _passkey,
    _transport,
    build_c1_corpus,
)
from .cxf import inflate_large_blob
from .model import b64url, unb64url
from .protocol import validate_protocol


HTML = b"<!doctype html><meta charset=utf-8><title>PasskeyTransit Phase 7 RP</title><p>ready</p>"
ASSERT_CHALLENGE = hashlib.sha256(b"passkeytransit-phase7-browser-assertion-v1").digest()
PRF_SALT = hashlib.sha256(b"passkeytransit-phase7-prf-first-v1").digest()


def resolve_browser_path(explicit: Path | None = None) -> Path:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit)
    elif os.environ.get("PASSKEYTRANSIT_BROWSER"):
        candidates.append(Path(os.environ["PASSKEYTRANSIT_BROWSER"]))
    else:
        for executable in ("msedge", "chrome", "chromium", "chromium-browser"):
            found = shutil.which(executable)
            if found:
                candidates.append(Path(found))
        if os.name == "nt":
            for variable, relative in (
                ("PROGRAMFILES(X86)", "Microsoft/Edge/Application/msedge.exe"),
                ("PROGRAMFILES", "Microsoft/Edge/Application/msedge.exe"),
                ("PROGRAMFILES", "Google/Chrome/Application/chrome.exe"),
                ("LOCALAPPDATA", "Google/Chrome/Application/chrome.exe"),
            ):
                if os.environ.get(variable):
                    candidates.append(Path(os.environ[variable]) / relative)
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError("Chromium browser not found; set PASSKEYTRANSIT_BROWSER or pass --browser")


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(HTML)))
        self.end_headers()
        self.wfile.write(HTML)

    def log_message(self, format: str, *args: object) -> None:
        return


@contextmanager
def _rp_server() -> Iterator[int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _standard_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _authenticate(page: Any, rp_id: str, credential_id: bytes) -> dict[str, Any]:
    return page.evaluate(
        r"""async ({challenge, rpId, credentialId, prfSalt}) => {
          const decode = value => {
            const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
            const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
            return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
          };
          const encode = value => {
            if (value === null || value === undefined) return null;
            const bytes = new Uint8Array(value);
            let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte);
            return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
          };
          const assertion = await navigator.credentials.get({publicKey: {
            challenge: decode(challenge), rpId,
            allowCredentials: [{type: 'public-key', id: decode(credentialId)}],
            userVerification: 'required',
            extensions: {largeBlob: {read: true}, prf: {eval: {first: decode(prfSalt)}}}, timeout: 10000
          }});
          const ext = assertion.getClientExtensionResults();
          return {
            rawId: encode(assertion.rawId), authenticatorData: encode(assertion.response.authenticatorData),
            clientDataJSON: encode(assertion.response.clientDataJSON), signature: encode(assertion.response.signature),
            userHandle: encode(assertion.response.userHandle),
            largeBlob: ext.largeBlob && ext.largeBlob.blob ? encode(ext.largeBlob.blob) : null,
            prfFirst: ext.prf && ext.prf.results && ext.prf.results.first ? encode(ext.prf.results.first) : null
          };
        }""",
        {"challenge": b64url(ASSERT_CHALLENGE), "rpId": rp_id, "credentialId": b64url(credential_id), "prfSalt": b64url(PRF_SALT)},
    )


def _verify(assertion: dict[str, Any], source_key: dict[str, Any], origin: str) -> dict[str, bool]:
    credential_id = unb64url(source_key["credentialId"])
    user_handle = unb64url(source_key["userHandle"])
    authenticator_data = unb64url(assertion["authenticatorData"])
    client_json = unb64url(assertion["clientDataJSON"])
    client = json.loads(client_json)
    public_key = serialization.load_der_private_key(unb64url(source_key["key"]), password=None).public_key()
    signature_valid = True
    try:
        public_key.verify(
            unb64url(assertion["signature"]),
            authenticator_data + hashlib.sha256(client_json).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature:
        signature_valid = False
    flags = authenticator_data[32]
    return {
        "credential_id": unb64url(assertion["rawId"]) == credential_id,
        "user_handle": unb64url(assertion["userHandle"]) == user_handle,
        "challenge": unb64url(client["challenge"]) == ASSERT_CHALLENGE,
        "origin": client["origin"] == origin,
        "type": client["type"] == "webauthn.get",
        "rp_id_hash": authenticator_data[:32] == hashlib.sha256(source_key["rpId"].encode()).digest(),
        "user_present": bool(flags & 0x01),
        "user_verified": bool(flags & 0x04),
        "signature": signature_valid,
        "counter_zero": int.from_bytes(authenticator_data[33:37], "big") == 0,
    }


def _prepare_cases(protocol: dict[str, Any], calibration: bool) -> list[tuple[int, str, dict[str, Any], dict[str, Any]]]:
    corpus = build_c1_corpus(protocol)
    if calibration:
        corpus = [item for item in corpus if item[0] % 32 == 0]
    routes = {route["id"]: route for route in protocol["routes"]}
    cases = [(index, stratum, source, routes[route_id]) for index, stratum, source in corpus for route_id in protocol["campaigns"]["C1"]["route_ids"]]
    random.Random(int(protocol["seed"])).shuffle(cases)
    return cases


def _migrate(source: dict[str, Any], route: dict[str, Any], properties: set[str]) -> tuple[dict[str, Any], set[str]]:
    current = copy.deepcopy(source)
    declarations: set[str] = set()
    chain = list(map(str, route["chain"]))
    for source_provider, destination in zip(chain, chain[1:]):
        current = _transport(current, source_provider, destination)
        current, declared = _apply_profile(
            current, destination, source_document=source, required_properties=properties
        )
        declarations.update(declared)
    return current, declarations


def _browser_oracles(
    source: dict[str, Any], migrated: dict[str, Any], properties: set[str], assertion: dict[str, Any], checks: dict[str, bool]
) -> dict[str, dict[str, Any]]:
    oracles = _evaluate(source, migrated, properties)
    assertion_pass = all(checks.values())
    oracles["webauthn_assertion"] = _oracle("PASS" if assertion_pass else "FAIL", checks)
    oracles["uv"] = _oracle("PASS" if checks["user_verified"] else "FAIL", checks["user_verified"])
    if "large_blob" in properties:
        expected = inflate_large_blob(_passkey(source))
        observed = unb64url(assertion["largeBlob"]) if assertion.get("largeBlob") else None
        oracles["large_blob"] = _oracle(
            "PASS" if expected == observed else "FAIL",
            [hashlib.sha256(expected or b"").hexdigest(), hashlib.sha256(observed or b"").hexdigest()],
        )
    return {name: oracles[name] for name in ORACLES}


def _assertion_evidence(assertion: dict[str, Any], checks: dict[str, bool], authenticator: str) -> dict[str, Any]:
    fields = ("rawId", "authenticatorData", "clientDataJSON", "signature", "userHandle", "largeBlob", "prfFirst")
    return {
        "checks": checks,
        "artifact_sha256": {
            name: hashlib.sha256(unb64url(assertion[name])).hexdigest() if assertion.get(name) else None
            for name in fields
        },
        "prf_requested": True,
        "prf_observed": assertion.get("prfFirst") is not None,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "authenticator_id_hash": hashlib.sha256(authenticator.encode()).hexdigest(),
    }


def _repeat_outcome(row: dict[str, Any]) -> bytes:
    return _canonical({
        "credential_id_hash": row["credential_id_hash"],
        "route_id": row["route_id"],
        "execution_status": row["execution_status"],
        "semantic_class": row["semantic_class"],
        "declared_losses": row["declared_losses"],
        "oracle_statuses": {name: row["oracles"][name]["status"] for name in ORACLES},
        "basic_auth_pass": row["basic_auth_pass"],
        "false_reassurance": row["false_reassurance"],
    })


def run_browser_c1(protocol_path: Path, browser_path: Path, output_dir: Path, *, calibration: bool) -> dict[str, Any]:
    mode = "calibration" if calibration else "full"
    prefix = f"c1_phase7_{mode}"
    raw_path = output_dir / f"{prefix}_attempts.jsonl"
    summary_path = output_dir / f"{prefix}_summary.json"
    manifest_path = output_dir / f"{prefix}_manifest.json"
    existing = [path for path in (raw_path, summary_path, manifest_path) if path.exists()]
    if existing:
        raise FileExistsError(f"browser campaign output is immutable: {existing[0]}")
    if not browser_path.is_file():
        raise FileNotFoundError(browser_path)
    validate_protocol(protocol_path)
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    cases = _prepare_cases(protocol, calibration)
    repetitions = 1 if calibration else int(protocol["campaigns"]["C1"]["repetitions"])
    rows: list[dict[str, Any]] = []
    rp_ids = sorted({_passkey(source)["rpId"] for _, _, source, _ in cases})
    with _rp_server() as port, sync_playwright() as playwright:
        origins = {rp_id: f"http://{rp_id}:{port}" for rp_id in rp_ids}
        args = [
            "--no-first-run", "--no-default-browser-check",
            "--host-resolver-rules=" + ",".join(f"MAP {rp_id} 127.0.0.1" for rp_id in rp_ids),
            "--unsafely-treat-insecure-origin-as-secure=" + ",".join(origins.values()),
        ]
        browser = playwright.chromium.launch(executable_path=str(browser_path), headless=True, args=args)
        try:
            context = browser.new_context()
            surfaces: dict[str, tuple[Any, Any, str]] = {}
            cdp_metadata: dict[str, Any] | None = None
            for rp_id in rp_ids:
                page = context.new_page()
                page.goto(origins[rp_id], wait_until="domcontentloaded")
                cdp = context.new_cdp_session(page)
                cdp.send("WebAuthn.enable", {"enableUI": False})
                if cdp_metadata is None:
                    browser_metadata = cdp.send("Browser.getVersion")
                    schema = cdp.send("Schema.getDomains")
                    cdp_metadata = {
                        "protocol_version": browser_metadata.get("protocolVersion"),
                        "product": browser_metadata.get("product"),
                        "schema_sha256": hashlib.sha256(_canonical(schema)).hexdigest(),
                    }
                authenticator = cdp.send(
                    "WebAuthn.addVirtualAuthenticator",
                    {"options": {"protocol": "ctap2", "ctap2Version": "ctap2_1", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True, "hasLargeBlob": True, "hasPrf": True, "automaticPresenceSimulation": True, "isUserVerified": True}},
                )["authenticatorId"]
                surfaces[rp_id] = (page, cdp, authenticator)
            for repetition in range(repetitions):
                for index, stratum, source, route in cases:
                    properties = set(map(str, protocol["feature_strata"][int(stratum[1:])]["properties"]))
                    source_key = _passkey(source)
                    chain = list(map(str, route["chain"]))
                    common = {
                        "protocol_id": protocol["protocol_id"], "campaign_id": "C1",
                        "run_id": f"phase7-browser-{mode}-r{repetition + 1}",
                        "attempt_id": f"C1-browser-{mode}-r{repetition + 1}-c{index:03d}-{route['id']}",
                        "credential_id_hash": hashlib.sha256(unb64url(source_key["credentialId"])).hexdigest(),
                        "feature_stratum": stratum, "route_id": route["id"], "seed": protocol["seed"],
                        "provider_chain": chain, "hop_count": len(chain) - 1, "mutation_id": None,
                        "failure_point": None, "retry_index": 0, "normative_class": "NOT_ASSESSED",
                    }
                    try:
                        migrated, declarations = _migrate(source, route, properties)
                    except StrictPreservationError as exc:
                        oracles = {name: _oracle("NOT_APPLICABLE", "strict import rejected before browser ceremony") for name in ORACLES}
                        oracles["cxf_structure"] = _oracle("PASS", {"strict_rejected_losses": sorted(exc.losses)})
                        oracles["custody_ground_truth"] = _oracle("PASS", "instrumented in-process provider chain")
                        rows.append({
                            **common, "execution_status": "REJECTED", "oracles": oracles,
                            "declared_losses": [], "semantic_class": "NOT_APPLICABLE",
                            "basic_auth_pass": None, "false_reassurance": None,
                            "exclusion_reason": "strict-preservation-rejection", "browser_evidence": None,
                        })
                        continue
                    migrated_key = _passkey(migrated)
                    rp_id = source_key["rpId"]
                    page, cdp, authenticator = surfaces[rp_id]
                    credential_id = unb64url(migrated_key["credentialId"])
                    imported_blob = inflate_large_blob(migrated_key)
                    credential = {
                        "credentialId": _standard_b64(credential_id), "isResidentCredential": True,
                        "rpId": migrated_key["rpId"], "privateKey": _standard_b64(unb64url(migrated_key["key"])),
                        "userHandle": _standard_b64(unb64url(migrated_key["userHandle"])), "signCount": -1,
                        "userName": migrated_key["username"], "userDisplayName": migrated_key["userDisplayName"],
                    }
                    if imported_blob is not None:
                        credential["largeBlob"] = _standard_b64(imported_blob)
                    cdp.send("WebAuthn.addCredential", {"authenticatorId": authenticator, "credential": credential})
                    try:
                        assertion = _authenticate(page, rp_id, credential_id)
                        checks = _verify(assertion, source_key, origins[rp_id])
                    finally:
                        cdp.send("WebAuthn.removeCredential", {"authenticatorId": authenticator, "credentialId": _standard_b64(credential_id)})
                    oracles = _browser_oracles(source, migrated, properties, assertion, checks)
                    semantic = _classify(oracles, declarations)
                    functional_fail = any(oracles[name]["status"] == "FAIL" for name in ("uv", "prf_uv", "prf_no_uv", "large_blob", "cred_blob"))
                    assertion_pass = oracles["webauthn_assertion"]["status"] == "PASS"
                    chain = list(map(str, route["chain"]))
                    rows.append(
                        {
                            **common, "execution_status": "IMPORTED",
                            "oracles": oracles, "declared_losses": sorted(declarations),
                            "semantic_class": semantic, "normative_class": "NOT_ASSESSED",
                            "basic_auth_pass": assertion_pass,
                            "false_reassurance": assertion_pass and functional_fail,
                            "exclusion_reason": None,
                            "browser_evidence": _assertion_evidence(assertion, checks, authenticator),
                        }
                    )
            browser_version = browser.version
        finally:
            browser.close()
    commit, dirty = _git_state(protocol_path.resolve().parent.parent)
    for row in rows:
        row["source_commit"] = commit
        row["environment_id"] = f"phase7-edge-browser-{mode}-v1"
    output_dir.mkdir(parents=True, exist_ok=True)
    with raw_path.open("x", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    seed = int(protocol["seed"])
    estimands = {
        "preserving_migration_yield": _bootstrap(rows, lambda row: row["semantic_class"] == "PASS", lambda row: True, seed + 21),
        "conditional_semantic_preservation": _bootstrap(rows, lambda row: row["semantic_class"] == "PASS", lambda row: row["execution_status"] == "IMPORTED", seed + 22),
        "silent_degradation_rate": _bootstrap(rows, lambda row: row["semantic_class"] == "DEGRADED_SILENT", lambda row: row["execution_status"] == "IMPORTED", seed + 23),
        "false_reassurance_rate": _bootstrap(rows, lambda row: row["false_reassurance"] is True, lambda row: row["basic_auth_pass"] is True, seed + 24),
    }
    repeat_equivalent: bool | None = None
    if not calibration:
        per_rep = len(cases)
        repeat_equivalent = all(_repeat_outcome(rows[i]) == _repeat_outcome(rows[i + per_rep]) for i in range(per_rep))
    summary = {
        "protocol_id": protocol["protocol_id"], "campaign_id": "C1", "mode": mode,
        "evidence_class": "browser-webauthn-reference-policy-control", "attempt_count": len(rows),
        "credential_count": len({row["credential_id_hash"] for row in rows}), "route_count": 12,
        "repetitions": repetitions, "execution_statuses": dict(Counter(row["execution_status"] for row in rows)),
        "semantic_classes": dict(Counter(row["semantic_class"] for row in rows)),
        "oracle_statuses": {name: dict(Counter(row["oracles"][name]["status"] for row in rows)) for name in ORACLES},
        "estimands": estimands,
        "design_result_cells": _design_cell_summary(rows),
        "paired_route_comparisons": _paired_route_comparisons(rows, protocol),
        "repeat_equivalent": repeat_equivalent,
        "confirmatory_provider_claims_authorized": False,
    }
    with summary_path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(summary, indent=2) + "\n")
    project_root = protocol_path.resolve().parent.parent
    manifest = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(), "passkeytransit_version": __version__,
        "python": sys.version, "platform": platform.platform(), "source_commit": commit, "source_dirty": dirty,
        "protocol_sha256": hashlib.sha256(protocol_path.read_bytes()).hexdigest(),
        "specification_baseline": protocol["specification_baseline"],
        "dependency_lock_sha256": hashlib.sha256((project_root / "requirements.lock").read_bytes()).hexdigest(),
        "browser": {"path": str(browser_path), "version": browser_version, "sha256": hashlib.sha256(browser_path.read_bytes()).hexdigest()},
        "cdp": cdp_metadata,
        "playwright_version": version("playwright"), "raw_sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
        "summary_sha256": hashlib.sha256(summary_path.read_bytes()).hexdigest(),
        "limitations": ["reference policies and Chromium virtual authenticators are not commercial providers", "CDP cannot inject CXF HMAC/PRF or credBlob state", "SPC behavior is not exercised"],
    }
    with manifest_path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(manifest, indent=2) + "\n")
    return {"summary": summary, "manifest": manifest}
