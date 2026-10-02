from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from playwright.sync_api import sync_playwright

from .cross_runtime import _software_prf
from .cxf import assert_valid_passkey_document, build_passkey_document
from .fenko_provider import (
    FENKO_COMMIT, _assert, _canonical, _export, _extension_id,
    _import, _launch, _prf_witness, _sha, _vault,
)
from .model import b64url, generate_synthetic_passkey, unb64url
from .webauthn_lab import local_rp


def _ceremonies(page: Any, passkey: Any, origin: str,
                fixed_salt: bytes, other_salt: bytes) -> dict[str, Any]:
    first = _assert(page, passkey, origin, fixed_salt)
    first_witness = _prf_witness(page, passkey, origin, first)
    repeat = _assert(page, passkey, origin, fixed_salt)
    repeat_witness = _prf_witness(page, passkey, origin, repeat)
    other = _assert(page, passkey, origin, other_salt)
    other_witness = _prf_witness(page, passkey, origin, other)
    return {
        "first": first, "first_witness": first_witness,
        "repeat": repeat, "repeat_witness": repeat_witness,
        "other": other, "other_witness": other_witness,
    }


def _public_transcripts(ceremonies: dict[str, Any]) -> dict[str, Any]:
    return {label: item["transcript"] for label, item in ceremonies.items()}


def _one_run(playwright: Any, browser: Path, extension: Path, origin: str,
             temporary: Path, repetition: int) -> dict[str, Any]:
    passkey = generate_synthetic_passkey(20261002, repetition * 10 + 3).evolve(rp_id="localhost")
    uv_seed = hashlib.sha256(f"fenko-v2-roundtrip-uv-{repetition}".encode()).digest()
    no_uv_seed = hashlib.sha256(f"fenko-v2-roundtrip-no-uv-{repetition}".encode()).digest()
    source_document = build_passkey_document(
        passkey, timestamp=1790940608, hmac_with_uv=uv_seed,
        hmac_without_uv=no_uv_seed,
    )
    assert_valid_passkey_document(source_document)
    fixed_salt = hashlib.sha256(b"fenko-v2-roundtrip-fixed-salt").digest()
    other_salt = hashlib.sha256(b"fenko-v2-roundtrip-other-salt").digest()
    source_standard_prf = _software_prf(source_document, fixed_salt, user_verified=True)

    source_context = _launch(playwright, browser, extension, temporary / "source")
    try:
        browser_version = source_context.browser.version if source_context.browser else "unknown"
        source_extension_id = _extension_id(source_context)
        source_import = _import(source_context, source_extension_id, source_document)
        source_count = len(_vault(source_context, source_extension_id))
        exported = _export(source_context, source_extension_id)
        exported_credential = next(
            credential
            for account in exported.get("accounts", [])
            for item in account.get("items", [])
            for credential in item.get("credentials", [])
            if credential.get("credentialId") == b64url(passkey.credential_id)
        )
        source_page = source_context.new_page()
        try:
            source_page.goto(origin, wait_until="domcontentloaded")
            source_page.wait_for_timeout(300)
            source_ceremonies = _ceremonies(
                source_page, passkey, origin, fixed_salt, other_salt,
            )
        finally:
            source_page.close()
    finally:
        source_context.close()

    destination_context = _launch(playwright, browser, extension, temporary / "destination")
    try:
        destination_extension_id = _extension_id(destination_context)
        destination_import = _import(destination_context, destination_extension_id, exported)
        destination_count = len(_vault(destination_context, destination_extension_id))
        destination_page = destination_context.new_page()
        try:
            destination_page.goto(origin, wait_until="domcontentloaded")
            destination_page.wait_for_timeout(300)
            destination_ceremonies = _ceremonies(
                destination_page, passkey, origin, fixed_salt, other_salt,
            )
        finally:
            destination_page.close()
    finally:
        destination_context.close()

    source_first = source_ceremonies["first"]["prf_first"]
    destination_first = destination_ceremonies["first"]["prf_first"]
    checks = {
        "source_imported": source_import["new_count"] == 1 and source_import["ui_success"] and source_count == 1,
        "destination_imported": destination_import["new_count"] == 1 and destination_import["ui_success"] and destination_count == 1,
        "all_assertions_verified": all(
            all(value for key, value in result["verification"].items() if key != "sign_count")
            for result in (*source_ceremonies.values(), *destination_ceremonies.values())
        ),
        "all_prf_results_present": all(
            ceremonies[label]["prf_first"] is not None
            for ceremonies in (source_ceremonies, destination_ceremonies)
            for label in ("first", "repeat", "other")
        ),
        "exported_identity_present": exported_credential.get("userHandle") == b64url(passkey.user_handle),
        "zero_counter_at_export": exported_credential.get("signCount", 0) == 0,
    }
    outcomes = {
        "source_fixed_stable": source_first is not None and source_ceremonies["repeat"]["prf_first"] == source_first,
        "destination_fixed_stable": destination_first is not None and destination_ceremonies["repeat"]["prf_first"] == destination_first,
        "source_other_differs": source_first is not None and source_ceremonies["other"]["prf_first"] not in (None, source_first),
        "destination_other_differs": destination_first is not None and destination_ceremonies["other"]["prf_first"] not in (None, destination_first),
        "fixed_source_destination_equal": source_first is not None and destination_first == source_first,
        "other_source_destination_equal": source_ceremonies["other"]["prf_first"] is not None and destination_ceremonies["other"]["prf_first"] == source_ceremonies["other"]["prf_first"],
        "source_cxf_seed_mismatch": source_first is not None and unb64url(source_first) != source_standard_prf,
        "exported_prf_state_missing": exported_credential.get("fido2Extensions") == {},
    }
    functional_status = (
        "NOT_EVALUABLE" if not checks["all_prf_results_present"] else
        "PASS" if all(outcomes[key] for key in (
            "source_fixed_stable", "destination_fixed_stable", "source_other_differs",
            "destination_other_differs", "fixed_source_destination_equal",
            "other_source_destination_equal",
        )) else "FAIL"
    )
    return {
        "repetition": repetition,
        "browser_version": browser_version,
        "source_document_sha256": _sha(_canonical(source_document)),
        "exported_document_sha256": _sha(_canonical(exported)),
        "source_standard_prf_sha256": _sha(source_standard_prf),
        "export": {
            "version": exported.get("version"),
            "credential_count": sum(
                len(item.get("credentials", []))
                for account in exported.get("accounts", [])
                for item in account.get("items", [])
            ),
            "credential_id_sha256": _sha(passkey.credential_id),
            "user_handle_equal": exported_credential.get("userHandle") == b64url(passkey.user_handle),
            "sign_count": exported_credential.get("signCount", 0),
            "prf_extension_state_present": bool(exported_credential.get("fido2Extensions")),
        },
        "import": {"source": source_import, "destination": destination_import},
        "stored_counts": {"source": source_count, "destination": destination_count},
        "assertions": {
            "source": _public_transcripts(source_ceremonies),
            "destination": _public_transcripts(destination_ceremonies),
        },
        "checks": checks,
        "all_procedure_checks_pass": all(checks.values()),
        "outcomes": outcomes,
        "functional_prf_continuity_oracle": functional_status,
        "source_cxf_seed_oracle": (
            "NOT_EVALUABLE" if source_first is None else
            "FAIL" if outcomes["source_cxf_seed_mismatch"] else "PASS"
        ),
    }


def run_fenko_roundtrip(protocol_path: Path, vendor_root: Path,
                        browser: Path, output: Path) -> dict[str, Any]:
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    if protocol.get("protocol_id") != "passkeytransit-fenko-cxf-browser-roundtrip-v2.1":
        raise ValueError("unexpected roundtrip protocol")
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=vendor_root, text=True,
    ).strip()
    if revision != FENKO_COMMIT or revision != protocol["provider"]["source_revision"]:
        raise ValueError(f"Fenko revision mismatch: {revision}")
    extension = (vendor_root / "dist").resolve()
    if not (extension / "manifest.json").is_file():
        raise FileNotFoundError("Fenko extension build missing")
    if not browser.is_file():
        raise FileNotFoundError(browser)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"roundtrip evidence output is immutable: {output}")
    with tempfile.TemporaryDirectory(prefix="fenko-roundtrip-", dir=output.parent) as temporary:
        with local_rp() as origin, sync_playwright() as playwright:
            runs = [
                _one_run(
                    playwright, browser, extension, origin,
                    Path(temporary) / f"repetition-{repetition}", repetition,
                )
                for repetition in (1, 2)
            ]
    report = {
        "evidence_class": "selected-same-provider-browser-CXF-roundtrip",
        "protocol_id": protocol["protocol_id"],
        "protocol_sha256": _sha(protocol_path.read_bytes()),
        "provider": {
            "name": "Fenko Vault", "version": "0.12.0",
            "source_revision": revision,
            "source_file_sha256": {
                name: _sha((vendor_root / name).read_bytes())
                for name in ("src/porting/formats/cxf.ts", "src/porting/import.ts",
                             "src/porting/export.ts", "src/background/prf.ts")
            },
            "built_extension_sha256": {
                name: _sha((extension / name).read_bytes())
                for name in ("background.js", "import.js", "options.js", "webauthn-inject.js")
            },
        },
        "browser_version": runs[0]["browser_version"],
        "runner_sha256": _sha(Path(__file__).read_bytes()),
        "runs": runs,
        "all_procedure_checks_pass": all(run["all_procedure_checks_pass"] for run in runs),
        "limitations": [
            "both browser profiles use the same open provider revision",
            "the selected provider was inspected before this protocol was fixed",
            "Fenko exchanges CXF files here, not CXP messages",
            "functional PRF continuity does not imply original CXF seed preservation",
            "Fenko's exported CXF version marker is 0.0, outside the tested 1.0 profile",
        ],
    }
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
