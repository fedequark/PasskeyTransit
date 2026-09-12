from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
from pathlib import Path
from typing import Any, Iterator

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from playwright.sync_api import sync_playwright

from .cxf import (
    build_passkey_document,
    extract_first_passkey,
    inflate_large_blob,
    private_key_matches,
    validate_passkey_document,
)
from .model import SyntheticPasskey, b64url, unb64url


RP_ID = "localhost"
REGISTER_CHALLENGE = hashlib.sha256(b"passkeytransit-register-v1").digest()
ASSERT_CHALLENGE = hashlib.sha256(b"passkeytransit-assert-v1").digest()
USER_HANDLE = hashlib.sha256(b"passkeytransit-user-v1").digest()[:32]
LARGE_BLOB = b"PasskeyTransit phase-3 largeBlob ground truth"


HTML = b"""<!doctype html>
<meta charset="utf-8">
<title>PasskeyTransit WebAuthn Laboratory</title>
<main><h1>PasskeyTransit WebAuthn Laboratory</h1><p id="status">ready</p></main>
"""


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
def local_rp() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://localhost:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _standard_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode_cdp(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        return unb64url(value)


def _decode_b64url(value: str) -> bytes:
    return unb64url(value)


def _register(page: Any) -> dict[str, Any]:
    return page.evaluate(
        r"""async ({challenge, userId}) => {
          const decode = value => {
            const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
            const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
            return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
          };
          const encode = value => {
            const bytes = new Uint8Array(value);
            let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte);
            return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
          };
          const credential = await navigator.credentials.create({publicKey: {
            challenge: decode(challenge),
            rp: {id: 'localhost', name: 'PasskeyTransit Test RP'},
            user: {id: decode(userId), name: 'research@example.test', displayName: 'Research User'},
            pubKeyCredParams: [{type: 'public-key', alg: -7}],
            authenticatorSelection: {
              residentKey: 'required',
              requireResidentKey: true,
              userVerification: 'required'
            },
            attestation: 'none',
            timeout: 10000
          }});
          const publicKey = credential.response.getPublicKey();
          if (!publicKey) throw new Error('getPublicKey() returned null');
          return {
            id: credential.id,
            rawId: encode(credential.rawId),
            publicKeySpki: encode(publicKey),
            clientDataJSON: encode(credential.response.clientDataJSON),
            transports: credential.response.getTransports(),
            extensions: credential.getClientExtensionResults()
          };
        }""",
        {"challenge": b64url(REGISTER_CHALLENGE), "userId": b64url(USER_HANDLE)},
    )


def _authenticate(page: Any, credential_id: bytes) -> dict[str, Any]:
    return page.evaluate(
        r"""async ({challenge, credentialId}) => {
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
            challenge: decode(challenge),
            rpId: 'localhost',
            allowCredentials: [{type: 'public-key', id: decode(credentialId)}],
            userVerification: 'required',
            extensions: {largeBlob: {read: true}}
          }});
          const ext = assertion.getClientExtensionResults();
          return {
            rawId: encode(assertion.rawId),
            authenticatorData: encode(assertion.response.authenticatorData),
            clientDataJSON: encode(assertion.response.clientDataJSON),
            signature: encode(assertion.response.signature),
            userHandle: encode(assertion.response.userHandle),
            largeBlob: ext.largeBlob && ext.largeBlob.blob ? encode(ext.largeBlob.blob) : null,
            extensions: Object.keys(ext)
          };
        }""",
        {"challenge": b64url(ASSERT_CHALLENGE), "credentialId": b64url(credential_id)},
    )


def _verify_assertion(assertion: dict[str, Any], public_spki: bytes) -> dict[str, Any]:
    authenticator_data = _decode_b64url(assertion["authenticatorData"])
    client_data_json = _decode_b64url(assertion["clientDataJSON"])
    signature = _decode_b64url(assertion["signature"])
    client_data = json.loads(client_data_json)
    expected_rp_hash = hashlib.sha256(RP_ID.encode("ascii")).digest()
    flags = authenticator_data[32]
    sign_count = int.from_bytes(authenticator_data[33:37], "big")
    signed = authenticator_data + hashlib.sha256(client_data_json).digest()
    public_key = serialization.load_der_public_key(public_spki)
    public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    return {
        "challenge": _decode_b64url(client_data["challenge"]) == ASSERT_CHALLENGE,
        "origin": str(client_data["origin"]).startswith("http://localhost:"),
        "type": client_data["type"] == "webauthn.get",
        "rp_id_hash": authenticator_data[:32] == expected_rp_hash,
        "user_present": bool(flags & 0x01),
        "user_verified": bool(flags & 0x04),
        "signature": True,
        "sign_count": sign_count,
    }


def _git_state(project_root: Path) -> dict[str, Any]:
    def run(*args: str) -> str:
        return subprocess.check_output(args, cwd=project_root, text=True).strip()
    try:
        commit = run("git", "rev-parse", "HEAD")
        dirty = bool(run("git", "status", "--porcelain"))
    except Exception:
        return {"commit": None, "dirty": None}
    return {"commit": commit, "dirty": dirty}


def run_webauthn_migration(browser_path: Path, output_path: Path | None = None) -> dict[str, Any]:
    if not browser_path.is_file():
        raise FileNotFoundError(f"Chromium executable not found: {browser_path}")
    with local_rp() as origin, sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=str(browser_path),
            headless=True,
            args=["--no-first-run", "--no-default-browser-check"],
        )
        try:
            context = browser.new_context()
            page = context.new_page()
            cdp = context.new_cdp_session(page)
            cdp.send("WebAuthn.enable", {"enableUI": False})
            source_authenticator = cdp.send(
                "WebAuthn.addVirtualAuthenticator",
                {"options": {
                    "protocol": "ctap2",
                    "ctap2Version": "ctap2_1",
                    "transport": "internal",
                    "hasResidentKey": True,
                    "hasUserVerification": True,
                    "hasLargeBlob": True,
                    "hasPrf": True,
                    "automaticPresenceSimulation": True,
                    "isUserVerified": True,
                }},
            )["authenticatorId"]
            page.goto(origin, wait_until="domcontentloaded")
            registration = _register(page)
            source_credentials = cdp.send(
                "WebAuthn.getCredentials", {"authenticatorId": source_authenticator}
            )["credentials"]
            if len(source_credentials) != 1:
                raise RuntimeError(f"expected one registered credential, got {len(source_credentials)}")
            captured = source_credentials[0]
            credential_id = _decode_cdp(captured["credentialId"])
            private_key = _decode_cdp(captured["privateKey"])
            user_handle = _decode_cdp(captured.get("userHandle", ""))
            public_spki = _decode_b64url(registration["publicKeySpki"])
            source = SyntheticPasskey(
                credential_id=credential_id,
                rp_id=captured["rpId"],
                user_handle=user_handle,
                username=captured.get("userName", "research@example.test"),
                user_display_name=captured.get("userDisplayName", "Research User"),
                private_key_pkcs8=private_key,
                prf_secret=None,
                large_blob=LARGE_BLOB,
            )
            cxf_document = build_passkey_document(
                source,
                timestamp=1789167600,
                exporter_rp_id="passkeytransit.example.test",
            )
            cxf_findings = validate_passkey_document(cxf_document)
            if any(f.severity == "error" for f in cxf_findings):
                raise RuntimeError("generated CXF document failed validation")
            imported_passkey = extract_first_passkey(cxf_document)
            imported_blob = inflate_large_blob(imported_passkey)

            cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": source_authenticator})
            destination_authenticator = cdp.send(
                "WebAuthn.addVirtualAuthenticator",
                {"options": {
                    "protocol": "ctap2",
                    "ctap2Version": "ctap2_1",
                    "transport": "internal",
                    "hasResidentKey": True,
                    "hasUserVerification": True,
                    "hasLargeBlob": True,
                    "hasPrf": True,
                    "automaticPresenceSimulation": True,
                    "isUserVerified": True,
                }},
            )["authenticatorId"]
            cdp.send(
                "WebAuthn.addCredential",
                {
                    "authenticatorId": destination_authenticator,
                    "credential": {
                        "credentialId": _standard_b64(unb64url(imported_passkey["credentialId"])),
                        "isResidentCredential": True,
                        "rpId": imported_passkey["rpId"],
                        "privateKey": _standard_b64(unb64url(imported_passkey["key"])),
                        "userHandle": _standard_b64(unb64url(imported_passkey["userHandle"])),
                        "signCount": -1,
                        "largeBlob": _standard_b64(imported_blob or b""),
                        "userName": imported_passkey["username"],
                        "userDisplayName": imported_passkey["userDisplayName"],
                    },
                },
            )
            assertion = _authenticate(page, credential_id)
            verification = _verify_assertion(assertion, public_spki)
            destination_credentials = cdp.send(
                "WebAuthn.getCredentials", {"authenticatorId": destination_authenticator}
            )["credentials"]
            checks = {
                "registration_raw_id_matches_cdp": _decode_b64url(registration["rawId"]) == credential_id,
                "cxf_valid": not cxf_findings,
                "cxf_key_matches_registration": private_key_matches(imported_passkey, public_spki),
                "imported_credential_count": len(destination_credentials) == 1,
                "assertion_credential_id": _decode_b64url(assertion["rawId"]) == credential_id,
                "assertion_user_handle": _decode_b64url(assertion["userHandle"]) == user_handle,
                "large_blob": assertion["largeBlob"] is not None and _decode_b64url(assertion["largeBlob"]) == LARGE_BLOB,
                "signature_counter_zero": verification["sign_count"] == 0,
                **{f"assertion_{key}": value for key, value in verification.items() if key != "sign_count"},
            }
            project_root = Path(__file__).resolve().parents[2]
            result = {
                "evidence_class": "browser-webauthn-reference-migration",
                "browser": {"path": str(browser_path), "version": browser.version},
                "playwright_version": version("playwright"),
                "origin": origin,
                "rp_id": RP_ID,
                "credential_id_sha256": hashlib.sha256(credential_id).hexdigest(),
                "cxf_profile": "cxf-passkey-profile-ps-errata-20260309",
                "git": _git_state(project_root),
                "checks": checks,
                "all_checks_pass": all(checks.values()),
                "limitations": [
                    "reference migration using Chromium virtual authenticators, not a commercial provider",
                    "CDP cannot inject CXF hmacCredentials/PRF seeds, so PRF preservation is not evaluated",
                    "CDP signCount -1 is used to produce the CXF-required zero assertion counter semantics",
                ],
            }
            if output_path is not None:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            return result
        finally:
            browser.close()
