from __future__ import annotations

import hashlib
import hmac
import json
import re
import base64
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .cxf import build_passkey_document
from .model import b64url, generate_synthetic_passkey, unb64url


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _verify_transcript(transcript: dict[str, Any], expected_credential_hash: str,
                       expected_spki: bytes, expected_user_hash: str) -> bool:
    if transcript["credential_id_sha256"] != expected_credential_hash:
        return False
    if transcript["observed_credential_id_sha256"] != expected_credential_hash:
        return False
    if transcript["user_handle_sha256"] != expected_user_hash:
        return False
    if transcript["observed_user_handle_sha256"] != expected_user_hash:
        return False
    spki = unb64url(transcript["public_key_spki"])
    if spki != expected_spki:
        return False
    challenge = unb64url(transcript["challenge"])
    auth_data = unb64url(transcript["authenticator_data"])
    client_data_json = unb64url(transcript["client_data_json"])
    signature = unb64url(transcript["signature"])
    client_data = json.loads(client_data_json)
    if len(auth_data) < 37 or len(challenge) != 32:
        return False
    if client_data.get("challenge") != transcript["challenge"] or client_data.get("type") != "webauthn.get":
        return False
    if not re.fullmatch(r"http://localhost:\d+", client_data.get("origin", "")):
        return False
    if auth_data[:32] != hashlib.sha256(b"localhost").digest():
        return False
    if auth_data[32] & 0x05 != 0x05:
        return False
    signed = auth_data + hashlib.sha256(client_data_json).digest()
    try:
        serialization.load_der_public_key(spki).verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    except Exception:
        return False
    return True


def verify_fenko_report(report_path: Path, protocol_path: Path) -> dict[str, Any]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    protocol_bytes = protocol_path.read_bytes()
    if report.get("protocol_id") != "passkeytransit-external-provider-v2.0":
        raise ValueError("wrong evidence class")
    if report.get("protocol_sha256") != _sha(protocol_bytes):
        raise ValueError("protocol hash mismatch")
    if report.get("provider", {}).get("source_revision") != json.loads(protocol_bytes)["candidate"]["source_revision"]:
        raise ValueError("provider revision mismatch")

    rows = []
    report_text = report_path.read_text(encoding="utf-8")
    expected_assertions = {
        "basic", "prf_first", "prf_first_witness", "prf_repeat",
        "prf_repeat_witness", "prf_other_salt", "prf_other_salt_witness",
        "after_restart",
    }
    for run in report.get("runs", []):
        repetition = run["repetition"]
        if repetition not in (1, 2):
            raise ValueError("unexpected repetition")
        basic = generate_synthetic_passkey(20261002, repetition * 10 + 1).evolve(rp_id="localhost")
        prf = generate_synthetic_passkey(20261002, repetition * 10 + 2).evolve(rp_id="localhost")
        transcripts = run["assertions"]
        assertion_set_valid = set(transcripts) == expected_assertions
        assertions_valid = {}
        for label, transcript in transcripts.items():
            source = basic if label in ("basic", "after_restart") else prf
            assertions_valid[label] = _verify_transcript(
                transcript, _sha(source.credential_id), source.public_key_spki, _sha(source.user_handle)
            )

        witness_binding = {}
        for label in ("prf_first", "prf_repeat", "prf_other_salt"):
            parent = transcripts[label]
            digest = parent["prf_output_sha256"]
            if digest is None:
                witness_binding[label] = False
                continue
            expected_challenge = hashlib.sha256(
                b"passkeytransit-fenko-prf-witness-v1\0" + unb64url(parent["challenge"]) + bytes.fromhex(digest)
            ).digest()
            witness_binding[label] = unb64url(transcripts[label + "_witness"]["challenge"]) == expected_challenge

        uv_seed = hashlib.sha256(f"fenko-v2-uv-{repetition}".encode()).digest()
        salt = hashlib.sha256(b"fenko-v2-fixed-salt").digest()
        input_hash = hashlib.sha256(b"WebAuthn PRF\0" + salt).digest()
        expected_source_prf_hash = _sha(hmac.new(uv_seed, input_hash, hashlib.sha256).digest())
        source_prf_bytes = hmac.new(uv_seed, input_hash, hashlib.sha256).digest()
        no_uv_seed = hashlib.sha256(f"fenko-v2-no-uv-{repetition}".encode()).digest()
        source_documents = {
            "basic": build_passkey_document(basic, timestamp=1790940608),
            "prf": build_passkey_document(
                prf, timestamp=1790940608, hmac_with_uv=uv_seed,
                hmac_without_uv=no_uv_seed,
            ),
        }
        source_documents_valid = run["source_document_sha256"] == {
            name: _sha(json.dumps(document, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=False).encode())
            for name, document in source_documents.items()
        }
        sensitive_values = [
            b64url(value) for value in (
                basic.private_key_pkcs8, prf.private_key_pkcs8, basic.credential_id,
                prf.credential_id, uv_seed, no_uv_seed, source_prf_bytes,
            )
        ] + [
            base64.b64encode(value).decode("ascii") for value in (
                basic.private_key_pkcs8, prf.private_key_pkcs8, uv_seed, no_uv_seed, source_prf_bytes,
            )
        ]
        sensitive_absent = all(value not in report_text for value in sensitive_values)
        first_dest_hash = transcripts["prf_first"]["prf_output_sha256"]
        source_digest_valid = run["source_prf_output_sha256"] == expected_source_prf_hash
        prf_status_valid = (
            first_dest_hash is not None and first_dest_hash != expected_source_prf_hash
            and run["prf_preservation_oracle"] == "FAIL"
        )
        prf_digest_relation_valid = (
            first_dest_hash is not None
            and transcripts["prf_repeat"]["prf_output_sha256"] == first_dest_hash
            and transcripts["prf_other_salt"]["prf_output_sha256"] not in (None, first_dest_hash)
            and all(transcripts[label]["prf_output_sha256"] is None for label in (
                "basic", "after_restart", "prf_first_witness", "prf_repeat_witness",
                "prf_other_salt_witness",
            ))
        )
        counts = run["counts"]
        storage_counts_valid = counts == {
            "after_basic": 1, "after_bad_key": 1, "after_prf": 2,
            "after_duplicate": 2, "after_restart": 2,
        }
        imports = run["import"]
        import_summary_valid = (
            imports["basic"]["new_count"] == 1 and imports["basic"]["ui_success"]
            and imports["prf"]["new_count"] == 1 and imports["prf"]["ui_success"]
            and imports["bad_key"]["new_count"] == 0
            and imports["duplicate"]["duplicate_count"] == 1
        )
        export = run["export"]
        export_summary_valid = (
            export["version"] == {"major": 0, "minor": 0}
            and export["credential_count"] == 2
            and export["basic_user_handle_equal"] and export["prf_user_handle_equal"]
            and not export["basic_username_equal"] and not export["prf_username_equal"]
            and not export["prf_extension_state_present"]
        )
        observations_valid = run["observations"] == {
            "source_prf_not_preserved": prf_status_valid,
            "exported_prf_state_missing": not export["prf_extension_state_present"],
        }
        harness_checks_valid = (
            run["all_harness_checks_pass"] is True
            and all(value is True for value in run["checks"].values())
        )
        rows.append({
            "repetition": repetition,
            "assertion_set_valid": assertion_set_valid,
            "assertions_valid": assertions_valid,
            "witness_binding": witness_binding,
            "source_documents_valid": source_documents_valid,
            "source_digest_valid": source_digest_valid,
            "prf_status_valid": prf_status_valid,
            "prf_digest_relation_valid": prf_digest_relation_valid,
            "storage_counts_valid": storage_counts_valid,
            "import_summary_valid": import_summary_valid,
            "export_summary_valid": export_summary_valid,
            "observations_valid": observations_valid,
            "sensitive_absent": sensitive_absent,
            "checks_consistent": harness_checks_valid,
        })
    verified = report.get("all_harness_checks_pass") is True and len(rows) == 2 and {r["repetition"] for r in rows} == {1, 2} and all(
        r["assertion_set_valid"] and r["source_documents_valid"] and
        all(r["assertions_valid"].values()) and all(r["witness_binding"].values())
        and r["source_digest_valid"] and r["prf_status_valid"] and r["prf_digest_relation_valid"]
        and r["storage_counts_valid"] and r["import_summary_valid"]
        and r["export_summary_valid"] and r["observations_valid"] and r["sensitive_absent"]
        and r["checks_consistent"] for r in rows
    )
    summary = {
        "repetitions": len(rows),
        "signed_assertions_verified": sum(sum(row["assertions_valid"].values()) for row in rows),
        "prf_witness_bindings_verified": sum(sum(row["witness_binding"].values()) for row in rows),
        "source_prf_mismatch_runs": sum(row["prf_status_valid"] for row in rows),
        "missing_export_prf_state_runs": sum(
            not run["export"]["prf_extension_state_present"] for run in report.get("runs", [])
        ),
        "bad_key_rejected_runs": sum(
            run["import"]["bad_key"]["new_count"] == 0 and
            run["counts"]["after_basic"] == run["counts"]["after_bad_key"]
            for run in report.get("runs", [])
        ),
        "duplicate_skipped_runs": sum(
            run["import"]["duplicate"]["duplicate_count"] == 1 and
            run["counts"]["after_prf"] == run["counts"]["after_duplicate"]
            for run in report.get("runs", [])
        ),
        "restart_persisted_runs": sum(
            run["counts"]["after_restart"] == 2 and row["assertions_valid"]["after_restart"]
            for run, row in zip(report.get("runs", []), rows)
        ),
    }
    return {"evidence_class": "independent-public-transcript-recalculation",
            "report_sha256": _sha(report_path.read_bytes()), "verified": verified,
            "summary": summary, "rows": rows}
