from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from playwright.sync_api import BrowserContext, Page, sync_playwright

from .cross_runtime import _software_prf
from .cxf import assert_valid_passkey_document, build_passkey_document
from .model import SyntheticPasskey, b64url, generate_synthetic_passkey, unb64url
from .webauthn_lab import _verify_assertion, local_rp


FENKO_COMMIT = "2d873fbe25257250de6e322e9d785b97b17a544f"

START_ASSERTION = r"""({challenge, credentialId, salt}) => {
  const dec = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)), c=>c.charCodeAt(0));
  const enc = a => a == null ? null : btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  const extensions = salt ? {prf:{eval:{first:dec(salt)}}} : undefined;
  window.__passkeyTransitPending = navigator.credentials.get({publicKey:{
    challenge:dec(challenge),rpId:'localhost',
    allowCredentials:[{type:'public-key',id:dec(credentialId)}],
    userVerification:'preferred',extensions,timeout:10000
  }}).then(a => ({rawId:enc(a.rawId),authenticatorData:enc(a.response.authenticatorData),
    clientDataJSON:enc(a.response.clientDataJSON),signature:enc(a.response.signature),
    userHandle:enc(a.response.userHandle),prfFirst:enc(a.getClientExtensionResults().prf?.results?.first)}));
  return true;
}"""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _extension_id(context: BrowserContext) -> str:
    if not context.service_workers:
        context.wait_for_event("serviceworker", timeout=10000)
    workers = [w.url for w in context.service_workers if w.url.endswith("/background.js")]
    if len(workers) != 1:
        raise RuntimeError(f"expected one Fenko service worker, got {len(workers)}")
    return workers[0].split("/")[2]


def _vault(context: BrowserContext, extension_id: str) -> list[dict[str, Any]]:
    page = context.new_page()
    try:
        page.goto(f"chrome-extension://{extension_id}/import.html")
        response = page.evaluate("async () => await chrome.runtime.sendMessage({type:'LIST_PASSKEYS'})")
        if not response.get("success"):
            raise RuntimeError(f"Fenko LIST_PASSKEYS failed: {response.get('error')}")
        return response.get("passkeys", [])
    finally:
        page.close()


def _import(context: BrowserContext, extension_id: str, document: dict[str, Any]) -> dict[str, Any]:
    page = context.new_page()
    try:
        page.goto(f"chrome-extension://{extension_id}/import.html")
        page.locator("#file-input").set_input_files({
            "name": "synthetic.cxf", "mimeType": "application/json", "buffer": _canonical(document)
        })
        page.locator("#preview.visible").wait_for(timeout=10000)
        status = page.locator("#status").inner_text()
        new_count = page.locator(".preview-item-status.new").count()
        duplicate_count = page.locator(".preview-item-status.duplicate").count()
        warnings = page.locator(".preview-warnings").count()
        if new_count:
            page.locator("#import-btn").click()
            page.locator("#status.success").wait_for(state="attached", timeout=10000)
            status = page.locator("#status").inner_text()
        return {"new_count": new_count, "duplicate_count": duplicate_count, "warning_count": warnings,
                "ui_success": page.locator("#status.success").count() == 1, "status_sha256": _sha(status.encode())}
    finally:
        page.close()


def _assert(page: Page, source: SyntheticPasskey, origin: str, salt: bytes | None = None,
            challenge: bytes | None = None) -> dict[str, Any]:
    challenge = challenge or secrets.token_bytes(32)
    page.evaluate(START_ASSERTION, {
        "challenge": b64url(challenge), "credentialId": b64url(source.credential_id),
        "salt": b64url(salt) if salt is not None else None,
    })
    page.locator("#pkv-continue").click(timeout=10000)
    assertion = page.evaluate("async () => await window.__passkeyTransitPending")
    verification = _verify_assertion(assertion, source.public_key_spki, challenge)
    client_data = json.loads(unb64url(assertion["clientDataJSON"]))
    verification["exact_origin"] = client_data.get("origin") == origin
    verification["credential_id"] = unb64url(assertion["rawId"]) == source.credential_id
    verification["user_handle"] = assertion.get("userHandle") == b64url(source.user_handle)
    prf_directly_signed = (
        unb64url(assertion["prfFirst"]) in unb64url(assertion["authenticatorData"])
        if salt is not None and assertion.get("prfFirst") else None
    )
    public_transcript = {
        "challenge": b64url(challenge), "public_key_spki": b64url(source.public_key_spki),
        "credential_id_sha256": _sha(source.credential_id),
        "observed_credential_id_sha256": _sha(unb64url(assertion["rawId"])),
        "authenticator_data": assertion["authenticatorData"],
        "client_data_json": assertion["clientDataJSON"], "signature": assertion["signature"],
        "user_handle_sha256": _sha(source.user_handle),
        "observed_user_handle_sha256": _sha(unb64url(assertion["userHandle"])) if assertion.get("userHandle") else None,
        "prf_output_sha256": _sha(unb64url(assertion["prfFirst"])) if assertion.get("prfFirst") else None,
    }
    return {"verification": verification, "transcript": public_transcript,
            "prf_first": assertion.get("prfFirst"), "prf_directly_signed": prf_directly_signed}


def _prf_witness(page: Page, source: SyntheticPasskey, origin: str, observed: dict[str, Any]) -> dict[str, Any]:
    digest_hex = observed["transcript"]["prf_output_sha256"]
    if digest_hex is None:
        raise RuntimeError("PRF result is absent; witness cannot be created")
    prior_challenge = unb64url(observed["transcript"]["challenge"])
    challenge = hashlib.sha256(
        b"passkeytransit-fenko-prf-witness-v1\0" + prior_challenge + bytes.fromhex(digest_hex)
    ).digest()
    return _assert(page, source, origin, challenge=challenge)


def _export(context: BrowserContext, extension_id: str) -> dict[str, Any]:
    page = context.new_page()
    try:
        page.goto(f"chrome-extension://{extension_id}/options.html")
        page.locator('[data-section="data"]').click()
        page.locator("#export-format").select_option("cxf")
        page.once("dialog", lambda dialog: dialog.accept())
        with page.expect_download(timeout=10000) as download_info:
            page.locator("#export-all-btn").click()
        downloaded = Path(download_info.value.path())
        try:
            return json.loads(downloaded.read_text(encoding="utf-8"))
        finally:
            downloaded.unlink(missing_ok=True)
    finally:
        page.close()


def _launch(playwright: Any, browser: Path, extension: Path, profile: Path) -> BrowserContext:
    return playwright.chromium.launch_persistent_context(
        user_data_dir=str(profile), executable_path=str(browser), headless=True, accept_downloads=True,
        ignore_default_args=["--disable-extensions"],
        args=[f"--disable-extensions-except={extension}", f"--load-extension={extension}",
              "--no-first-run", "--no-default-browser-check"],
    )


def _one_run(playwright: Any, browser: Path, extension: Path, origin: str, profile: Path, repetition: int) -> dict[str, Any]:
    basic = generate_synthetic_passkey(20261002, repetition * 10 + 1).evolve(rp_id="localhost")
    prf = generate_synthetic_passkey(20261002, repetition * 10 + 2).evolve(rp_id="localhost")
    uv_seed = hashlib.sha256(f"fenko-v2-uv-{repetition}".encode()).digest()
    no_uv_seed = hashlib.sha256(f"fenko-v2-no-uv-{repetition}".encode()).digest()
    basic_doc = build_passkey_document(basic, timestamp=1790940608)
    prf_doc = build_passkey_document(
        prf, timestamp=1790940608, hmac_with_uv=uv_seed, hmac_without_uv=no_uv_seed,
    )
    assert_valid_passkey_document(basic_doc)
    assert_valid_passkey_document(prf_doc)
    salt = hashlib.sha256(b"fenko-v2-fixed-salt").digest()
    other_salt = hashlib.sha256(b"fenko-v2-other-salt").digest()
    source_prf = _software_prf(prf_doc, salt, user_verified=True)

    context = _launch(playwright, browser, extension, profile)
    try:
        browser_version = context.browser.version if context.browser else "unknown"
        extension_id = _extension_id(context)
        basic_import = _import(context, extension_id, basic_doc)
        after_basic_count = len(_vault(context, extension_id))
        malformed_doc = json.loads(json.dumps(basic_doc))
        malformed_doc["accounts"][0]["items"][0]["credentials"][0]["key"] = "AA"
        malformed_doc["accounts"][0]["items"][0]["credentials"][0]["credentialId"] = b64url(secrets.token_bytes(32))
        bad_import = _import(context, extension_id, malformed_doc)
        after_bad_count = len(_vault(context, extension_id))
        prf_import = _import(context, extension_id, prf_doc)
        after_prf_count = len(_vault(context, extension_id))

        page = context.new_page()
        try:
            page.goto(origin, wait_until="domcontentloaded")
            page.wait_for_timeout(300)
            basic_assertion = _assert(page, basic, origin)
            prf_first = _assert(page, prf, origin, salt)
            prf_first_witness = _prf_witness(page, prf, origin, prf_first)
            prf_repeat = _assert(page, prf, origin, salt)
            prf_repeat_witness = _prf_witness(page, prf, origin, prf_repeat)
            prf_other = _assert(page, prf, origin, other_salt)
            prf_other_witness = _prf_witness(page, prf, origin, prf_other)
        finally:
            page.close()

        exported = _export(context, extension_id)
        exported_credentials = {
            item["credentials"][0]["credentialId"]: item["credentials"][0]
            for account in exported.get("accounts", []) for item in account.get("items", [])
            if item.get("credentials") and item["credentials"][0].get("type") == "passkey"
        }
        duplicate_import = _import(context, extension_id, basic_doc)
        after_duplicate_count = len(_vault(context, extension_id))
    finally:
        context.close()

    restarted = _launch(playwright, browser, extension, profile)
    try:
        restarted_id = _extension_id(restarted)
        after_restart_count = len(_vault(restarted, restarted_id))
        page = restarted.new_page()
        try:
            page.goto(origin, wait_until="domcontentloaded")
            page.wait_for_timeout(300)
            restart_assertion = _assert(page, basic, origin)
        finally:
            page.close()
    finally:
        restarted.close()

    exported_basic = exported_credentials.get(b64url(basic.credential_id), {})
    exported_prf = exported_credentials.get(b64url(prf.credential_id), {})
    first_output = prf_first["prf_first"]
    checks = {
        "basic_imported": basic_import["new_count"] == 1 and basic_import["ui_success"] and after_basic_count == 1,
        "bad_key_rejected_without_storage_change": bad_import["new_count"] == 0 and after_bad_count == 1,
        "prf_credential_imported": prf_import["new_count"] == 1 and prf_import["ui_success"] and after_prf_count == 2,
        "all_assertions_verified": all(
            all(v for k, v in result["verification"].items() if k != "sign_count")
            for result in (basic_assertion, prf_first, prf_first_witness, prf_repeat,
                           prf_repeat_witness, prf_other, prf_other_witness, restart_assertion)
        ),
        "prf_executed": first_output is not None,
        "prf_same_salt_stable": first_output is not None and prf_repeat["prf_first"] == first_output,
        "prf_different_salt_differs": first_output is not None and prf_other["prf_first"] not in (None, first_output),
        "prf_witnesses_bound_to_output_hashes": all(
            all(v for k, v in witness["verification"].items() if k != "sign_count")
            for witness in (prf_first_witness, prf_repeat_witness, prf_other_witness)
        ),
        "exported_identity_present": bool(exported_basic) and bool(exported_prf),
        "duplicate_skipped": duplicate_import["duplicate_count"] == 1 and after_duplicate_count == 2,
        "restart_persisted_and_signed": after_restart_count == 2 and all(
            v for k, v in restart_assertion["verification"].items() if k != "sign_count"
        ),
    }
    prf_status = (
        "NOT_EVALUABLE" if first_output is None else
        "PASS" if unb64url(first_output) == source_prf else "FAIL"
    )
    return {
        "repetition": repetition,
        "browser_version": browser_version,
        "source_document_sha256": {"basic": _sha(_canonical(basic_doc)), "prf": _sha(_canonical(prf_doc))},
        "source_prf_output_sha256": _sha(source_prf),
        "import": {"basic": basic_import, "bad_key": bad_import, "prf": prf_import, "duplicate": duplicate_import},
        "counts": {"after_basic": after_basic_count, "after_bad_key": after_bad_count,
                   "after_prf": after_prf_count, "after_duplicate": after_duplicate_count,
                   "after_restart": after_restart_count},
        "export": {"version": exported.get("version"), "credential_count": len(exported_credentials),
                   "basic_user_handle_equal": exported_basic.get("userHandle") == b64url(basic.user_handle),
                   "prf_user_handle_equal": exported_prf.get("userHandle") == b64url(prf.user_handle),
                   "basic_username_equal": exported_basic.get("userName") == basic.username,
                   "prf_username_equal": exported_prf.get("userName") == prf.username,
                   "prf_extension_state_present": bool(exported_prf.get("fido2Extensions"))},
        "assertions": {"basic": basic_assertion["transcript"], "prf_first": prf_first["transcript"],
                       "prf_first_witness": prf_first_witness["transcript"],
                       "prf_repeat": prf_repeat["transcript"],
                       "prf_repeat_witness": prf_repeat_witness["transcript"],
                       "prf_other_salt": prf_other["transcript"],
                       "prf_other_salt_witness": prf_other_witness["transcript"],
                       "after_restart": restart_assertion["transcript"]},
        "prf_result_directly_in_signed_authenticator_data": prf_first["prf_directly_signed"],
        "checks": checks, "all_harness_checks_pass": all(checks.values()),
        "observations": {
            "source_prf_not_preserved": prf_status == "FAIL",
            "exported_prf_state_missing": exported_prf.get("fido2Extensions") == {},
        },
        "prf_preservation_oracle": prf_status,
    }


def run_fenko_provider(protocol_path: Path, vendor_root: Path, browser: Path, output: Path) -> dict[str, Any]:
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    if protocol.get("protocol_id") != "passkeytransit-external-provider-v2.0":
        raise ValueError("unexpected v2 protocol")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=vendor_root, text=True).strip()
    if revision != FENKO_COMMIT or revision != protocol["candidate"]["source_revision"]:
        raise ValueError(f"Fenko source revision mismatch: {revision}")
    extension = (vendor_root / "dist").resolve()
    if not (extension / "manifest.json").is_file():
        raise FileNotFoundError("Fenko extension build missing; run npm run build:chrome")
    if not browser.is_file():
        raise FileNotFoundError(browser)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"v2 evidence output is immutable: {output}")
    with tempfile.TemporaryDirectory(prefix="fenko-v2-", dir=output.parent) as temporary:
        with local_rp() as origin, sync_playwright() as playwright:
            runs = [
                _one_run(playwright, browser, extension, origin, Path(temporary) / f"profile-{n}", n)
                for n in (1, 2)
            ]
    result = {
        "evidence_class": "external-open-source-browser-provider-CXF-followup",
        "study_status": "prospective-source-informed-after-phase14",
        "protocol_id": protocol["protocol_id"], "protocol_sha256": _sha(protocol_path.read_bytes()),
        "provider": {"name": "Fenko Vault", "version": "0.12.0", "source_revision": revision,
                     "source_url": protocol["candidate"]["source_url"],
                     "source_file_sha256": {
                         name: _sha((vendor_root / name).read_bytes()) for name in (
                             "src/porting/formats/cxf.ts", "src/porting/import.ts",
                             "src/porting/export.ts", "src/background/prf.ts", "package-lock.json",
                         )
                     },
                     "built_extension_sha256": {
                         name: _sha((extension / name).read_bytes()) for name in (
                             "background.js", "import.js", "options.js", "webauthn-inject.js",
                         )
                     }},
        "browser_version": runs[0]["browser_version"],
        "runner_sha256": _sha(Path(__file__).read_bytes()),
        "runs": runs, "all_harness_checks_pass": all(run["all_harness_checks_pass"] for run in runs),
        "limitations": [
            "Fenko exchanges CXF files here, not CXP messages",
            "the provider source was inspected before protocol v2 was fixed",
            "source PRF expected value is a software standards control, not a source-browser ceremony",
            "Fenko is a developer/research vault; the result cannot be generalized to other providers",
        ],
    }
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result
