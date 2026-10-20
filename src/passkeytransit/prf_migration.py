from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
from pathlib import Path
from typing import Any

from playwright.sync_api import sync_playwright

from .cross_runtime import _node_call
from .cxf import build_passkey_document, extract_first_passkey, validate_passkey_document
from .cxp import ReplayCache, create_import_session, import_cxf
from .model import SyntheticPasskey, b64url, unb64url
from .webauthn_lab import RP_ID, _decode_b64url, _decode_cdp, _standard_b64, _verify_assertion, local_rp


REGISTER_PRF = r"""async ({challenge, userId}) => {
  const decode = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)), c=>c.charCodeAt(0));
  const encode = a => btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  const credential = await navigator.credentials.create({publicKey:{
    challenge:decode(challenge), rp:{id:'localhost',name:'PasskeyTransit Test RP'},
    user:{id:decode(userId),name:'research@example.test',displayName:'Research User'},
    pubKeyCredParams:[{type:'public-key',alg:-7}],
    authenticatorSelection:{residentKey:'required',userVerification:'required'},
    extensions:{prf:{}}, timeout:10000
  }});
  return {
    rawId:encode(credential.rawId), publicKeySpki:encode(credential.response.getPublicKey()),
    prfEnabled:credential.getClientExtensionResults().prf?.enabled === true
  };
}"""

AUTHENTICATE_PRF = r"""async ({challenge, credentialId, salt}) => {
  const decode = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)), c=>c.charCodeAt(0));
  const encode = a => a == null ? null : btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  const assertion = await navigator.credentials.get({publicKey:{
    challenge:decode(challenge), rpId:'localhost',
    allowCredentials:[{type:'public-key',id:decode(credentialId)}],
    userVerification:'required',extensions:{prf:{eval:{first:decode(salt)}}},timeout:10000
  }});
  const extensions = assertion.getClientExtensionResults();
  return {
    rawId:encode(assertion.rawId), authenticatorData:encode(assertion.response.authenticatorData),
    clientDataJSON:encode(assertion.response.clientDataJSON), signature:encode(assertion.response.signature),
    userHandle:encode(assertion.response.userHandle),
    prfFirst:encode(extensions.prf?.results?.first), prfExtensionPresent:'prf' in extensions
  };
}"""


def _prf_assertion(page: Any, credential_id: bytes, salt: bytes, spki: bytes) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    challenge = secrets.token_bytes(32)
    assertion = page.evaluate(AUTHENTICATE_PRF, {
        "challenge": b64url(challenge), "credentialId": b64url(credential_id), "salt": b64url(salt),
    })
    verification = _verify_assertion(assertion, spki, challenge)
    return assertion, verification, challenge


def _public_observation(stage: str, assertion: dict[str, Any], challenge: bytes, salt: bytes) -> dict[str, Any]:
    """Keep only public WebAuthn evidence; never retain a raw PRF output."""
    prf_output = assertion.get("prfFirst")
    return {
        "stage": stage,
        "challenge": b64url(challenge),
        "salt": b64url(salt),
        "raw_id": assertion["rawId"],
        "authenticator_data": assertion["authenticatorData"],
        "client_data_json": assertion["clientDataJSON"],
        "signature": assertion["signature"],
        "prf_present": prf_output is not None,
        "prf_output_sha256": hashlib.sha256(unb64url(prf_output)).hexdigest() if prf_output else None,
    }


def run_prf_migration(browser_path: Path, node_path: Path, node_script: Path, output: Path) -> dict[str, Any]:
    """Browser-executed PRF loss control through the experimental CXP exchange.

    This is a negative control: CDP can export a passkey's signing key but cannot
    export or inject its PRF seed. A destination PRF failure is expected.
    """
    if not browser_path.is_file():
        raise FileNotFoundError(browser_path)
    with local_rp() as origin, sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=str(browser_path), headless=True,
            args=["--no-first-run", "--no-default-browser-check"],
        )
        try:
            context = browser.new_context()
            page = context.new_page()
            cdp = context.new_cdp_session(page)
            cdp.send("WebAuthn.enable", {"enableUI": False})
            options = {
                "protocol": "ctap2", "ctap2Version": "ctap2_1", "transport": "internal",
                "hasResidentKey": True, "hasUserVerification": True, "hasLargeBlob": True,
                "hasPrf": True, "automaticPresenceSimulation": True, "isUserVerified": True,
            }
            source_id = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": options})["authenticatorId"]
            page.goto(origin, wait_until="domcontentloaded")
            registration = page.evaluate(REGISTER_PRF, {
                "challenge": b64url(secrets.token_bytes(32)), "userId": b64url(secrets.token_bytes(16)),
            })
            credential_id = unb64url(registration["rawId"])
            spki = unb64url(registration["publicKeySpki"])
            salt = hashlib.sha256(b"passkeytransit-executable-prf-salt-v1").digest()
            other_salt = hashlib.sha256(b"passkeytransit-executable-prf-other-salt-v1").digest()
            before, before_verification, before_challenge = _prf_assertion(page, credential_id, salt, spki)
            repeated, repeated_verification, repeated_challenge = _prf_assertion(page, credential_id, salt, spki)
            different, different_verification, different_challenge = _prf_assertion(page, credential_id, other_salt, spki)

            captured = cdp.send("WebAuthn.getCredentials", {"authenticatorId": source_id})["credentials"]
            if len(captured) != 1:
                raise RuntimeError(f"expected one source credential; got {len(captured)}")
            source_cdp = captured[0]
            source = SyntheticPasskey(
                credential_id=_decode_cdp(source_cdp["credentialId"]),
                rp_id=source_cdp["rpId"],
                user_handle=_decode_cdp(source_cdp["userHandle"]),
                username=source_cdp.get("userName", "research@example.test"),
                user_display_name=source_cdp.get("userDisplayName", "Research User"),
                private_key_pkcs8=_decode_cdp(source_cdp["privateKey"]),
                prf_secret=None,
                large_blob=None,
            )
            document = build_passkey_document(source, timestamp=1789167600)
            findings = validate_passkey_document(document)
            if any(f.severity == "error" for f in findings):
                raise RuntimeError("captured source CXF document is invalid")

            # A separately written Node exporter processes the actual browser
            # credential document; Python handles the importer side.
            session = create_import_session("importer.example.test")
            response = _node_call(node_path, node_script, {
                "operation": "export", "request": session.request, "document": document,
                "exporter": "exporter.example.test",
            })["response"]
            recovered = import_cxf(
                session, response, expected_exporter="exporter.example.test", replay_cache=ReplayCache()
            )
            recovered_passkey = extract_first_passkey(recovered)

            cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": source_id})
            destination_id = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": options})["authenticatorId"]
            cdp.send("WebAuthn.addCredential", {
                "authenticatorId": destination_id,
                "credential": {
                    "credentialId": _standard_b64(unb64url(recovered_passkey["credentialId"])),
                    "isResidentCredential": True, "rpId": recovered_passkey["rpId"],
                    "privateKey": _standard_b64(unb64url(recovered_passkey["key"])),
                    "userHandle": _standard_b64(unb64url(recovered_passkey["userHandle"])),
                    "signCount": -1, "userName": recovered_passkey["username"],
                    "userDisplayName": recovered_passkey["userDisplayName"],
                },
            })
            after, after_verification, after_challenge = _prf_assertion(page, credential_id, salt, spki)
            source_result = before.get("prfFirst")
            checks = {
                "source_registration_prf_enabled": registration["prfEnabled"],
                "source_prf_executed": source_result is not None,
                "same_salt_stable": source_result is not None and repeated.get("prfFirst") == source_result,
                "different_salt_changes_output": source_result is not None and different.get("prfFirst") not in (None, source_result),
                "all_assertion_signatures_valid": all(
                    all(v for k, v in verification.items() if k != "sign_count")
                    for verification in (before_verification, repeated_verification, different_verification, after_verification)
                ),
                "credential_id_preserved": _decode_b64url(after["rawId"]) == credential_id,
                "source_prf_state_not_exposed_in_cdp_fields": not any("prf" in key.lower() or "hmac" in key.lower() for key in source_cdp),
                "cxp_document_equal": recovered == document,
                "destination_prf_result_missing": after.get("prfFirst") is None,
            }
            result = {
                "evidence_class": "browser-executed-prf-loss-control-after-cross-runtime-exchange",
                "study_status": "post-inspection-exploratory",
                "node_script_sha256": hashlib.sha256(node_script.read_bytes()).hexdigest(),
                "python_runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "browser_version": browser.version,
                "node_version": subprocess.check_output([str(node_path), "--version"], text=True).strip(),
                "rp_id": RP_ID, "credential_id_sha256": hashlib.sha256(credential_id).hexdigest(),
                "source_prf_output_sha256": hashlib.sha256(unb64url(source_result)).hexdigest() if source_result else None,
                "public_transcript": {
                    "schema_version": 1,
                    "rp_id": RP_ID,
                    "credential_id": b64url(credential_id),
                    "public_key_spki": b64url(spki),
                    "observations": [
                        _public_observation("source_initial", before, before_challenge, salt),
                        _public_observation("source_repeat", repeated, repeated_challenge, salt),
                        _public_observation("source_other_salt", different, different_challenge, other_salt),
                        _public_observation("destination", after, after_challenge, salt),
                    ],
                },
                "source_cdp_fields": sorted(source_cdp),
                "checks": checks,
                "all_checks_pass": all(checks.values()),
                "interpretation": "PRF was executed before migration and absent after CDP-based import; this proves loss detection for this test path, not positive PRF preservation or provider behavior.",
                "limitations": [
                    "CDP getCredentials/addCredential does not expose or inject the PRF secret",
                    "the Node CXP implementation is project-authored and uses an experimental binding",
                    "Chromium virtual authenticators are not commercial credential providers",
                ],
            }
            output.parent.mkdir(parents=True, exist_ok=True)
            if output.exists():
                raise FileExistsError(f"PRF output is immutable: {output}")
            output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            return result
        finally:
            browser.close()
