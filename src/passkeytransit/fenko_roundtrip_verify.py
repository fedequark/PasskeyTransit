from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from .cxf import build_passkey_document
from .fenko_provider import _canonical, _sha
from .fenko_verify import _verify_transcript
from .model import b64url, generate_synthetic_passkey, unb64url


LABELS = {"first", "first_witness", "repeat", "repeat_witness", "other", "other_witness"}


def _verify_witnesses(transcripts: dict[str, Any]) -> dict[str, bool]:
    result = {}
    for label in ("first", "repeat", "other"):
        parent = transcripts[label]
        digest = parent["prf_output_sha256"]
        if digest is None:
            result[label] = False
            continue
        expected = hashlib.sha256(
            b"passkeytransit-fenko-prf-witness-v1\0"
            + unb64url(parent["challenge"]) + bytes.fromhex(digest)
        ).digest()
        result[label] = unb64url(transcripts[f"{label}_witness"]["challenge"]) == expected
    return result


def verify_fenko_roundtrip(report_path: Path, protocol_path: Path) -> dict[str, Any]:
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    protocol_bytes = protocol_path.read_bytes()
    protocol = json.loads(protocol_bytes)
    if report.get("protocol_id") != "passkeytransit-fenko-cxf-browser-roundtrip-v2.1":
        raise ValueError("wrong roundtrip evidence class")
    if report.get("protocol_sha256") != _sha(protocol_bytes):
        raise ValueError("protocol hash mismatch")
    if report.get("provider", {}).get("source_revision") != protocol["provider"]["source_revision"]:
        raise ValueError("provider revision mismatch")

    rows = []
    report_text = report_bytes.decode("utf-8")
    for run in report.get("runs", []):
        repetition = run["repetition"]
        if repetition not in (1, 2):
            raise ValueError("unexpected repetition")
        passkey = generate_synthetic_passkey(20261002, repetition * 10 + 3).evolve(rp_id="localhost")
        uv_seed = hashlib.sha256(f"fenko-v2-roundtrip-uv-{repetition}".encode()).digest()
        no_uv_seed = hashlib.sha256(f"fenko-v2-roundtrip-no-uv-{repetition}".encode()).digest()
        source_document = build_passkey_document(
            passkey, timestamp=1790940608, hmac_with_uv=uv_seed,
            hmac_without_uv=no_uv_seed,
        )
        source_document_valid = run["source_document_sha256"] == _sha(_canonical(source_document))
        fixed_salt = hashlib.sha256(b"fenko-v2-roundtrip-fixed-salt").digest()
        prf_input = hashlib.sha256(b"WebAuthn PRF\0" + fixed_salt).digest()
        standard_prf = hmac.new(uv_seed, prf_input, hashlib.sha256).digest()
        standard_digest_valid = run["source_standard_prf_sha256"] == _sha(standard_prf)

        assertion_set_valid = set(run["assertions"]) == {"source", "destination"} and all(
            set(run["assertions"][side]) == LABELS for side in ("source", "destination")
        )
        signatures = {}
        witnesses = {}
        for side in ("source", "destination"):
            transcripts = run["assertions"][side]
            signatures[side] = {
                label: _verify_transcript(
                    transcript, _sha(passkey.credential_id),
                    passkey.public_key_spki, _sha(passkey.user_handle),
                )
                for label, transcript in transcripts.items()
            }
            witnesses[side] = _verify_witnesses(transcripts)

        source = run["assertions"]["source"]
        destination = run["assertions"]["destination"]
        digest = lambda side, label: side[label]["prf_output_sha256"]
        recomputed_outcomes = {
            "source_fixed_stable": digest(source, "first") is not None and digest(source, "repeat") == digest(source, "first"),
            "destination_fixed_stable": digest(destination, "first") is not None and digest(destination, "repeat") == digest(destination, "first"),
            "source_other_differs": digest(source, "other") not in (None, digest(source, "first")),
            "destination_other_differs": digest(destination, "other") not in (None, digest(destination, "first")),
            "fixed_source_destination_equal": digest(source, "first") is not None and digest(source, "first") == digest(destination, "first"),
            "other_source_destination_equal": digest(source, "other") is not None and digest(source, "other") == digest(destination, "other"),
            "source_cxf_seed_mismatch": digest(source, "first") is not None and digest(source, "first") != _sha(standard_prf),
            "exported_prf_state_missing": not run["export"]["prf_extension_state_present"],
        }
        outcomes_valid = run["outcomes"] == recomputed_outcomes
        continuity_status = (
            "NOT_EVALUABLE" if any(digest(side, label) is None
                                   for side in (source, destination)
                                   for label in ("first", "repeat", "other")) else
            "PASS" if all(recomputed_outcomes[key] for key in (
                "source_fixed_stable", "destination_fixed_stable", "source_other_differs",
                "destination_other_differs", "fixed_source_destination_equal",
                "other_source_destination_equal",
            )) else "FAIL"
        )
        seed_status = (
            "NOT_EVALUABLE" if digest(source, "first") is None else
            "FAIL" if recomputed_outcomes["source_cxf_seed_mismatch"] else "PASS"
        )
        statuses_valid = (
            run["functional_prf_continuity_oracle"] == continuity_status
            and run["source_cxf_seed_oracle"] == seed_status
        )
        export = run["export"]
        export_summary_valid = (
            export["version"] == {"major": 0, "minor": 0}
            and export["credential_count"] == 1
            and export["credential_id_sha256"] == _sha(passkey.credential_id)
            and export["user_handle_equal"]
            and export["sign_count"] == 0
            and not export["prf_extension_state_present"]
        )
        import_summary_valid = (
            run["stored_counts"] == {"source": 1, "destination": 1}
            and all(run["import"][side]["new_count"] == 1
                    and run["import"][side]["ui_success"]
                    for side in ("source", "destination"))
        )
        procedure_valid = (
            run["all_procedure_checks_pass"] is True
            and all(value is True for value in run["checks"].values())
        )
        sensitive = (
            passkey.private_key_pkcs8, passkey.credential_id,
            uv_seed, no_uv_seed, standard_prf,
        )
        sensitive_absent = all(
            encoded not in report_text
            for value in sensitive
            for encoded in (b64url(value), base64.b64encode(value).decode("ascii"))
        )
        rows.append({
            "repetition": repetition,
            "source_document_valid": source_document_valid,
            "standard_digest_valid": standard_digest_valid,
            "assertion_set_valid": assertion_set_valid,
            "signatures": signatures,
            "witnesses": witnesses,
            "outcomes_valid": outcomes_valid,
            "statuses_valid": statuses_valid,
            "export_summary_valid": export_summary_valid,
            "import_summary_valid": import_summary_valid,
            "procedure_valid": procedure_valid,
            "sensitive_absent": sensitive_absent,
            "continuity_status": continuity_status,
            "source_seed_mismatch": recomputed_outcomes["source_cxf_seed_mismatch"],
            "exported_prf_state_missing": recomputed_outcomes["exported_prf_state_missing"],
        })
    verified = (
        report.get("all_procedure_checks_pass") is True
        and len(rows) == 2
        and {row["repetition"] for row in rows} == {1, 2}
        and all(
            all(row[key] for key in (
                "source_document_valid", "standard_digest_valid", "assertion_set_valid",
                "outcomes_valid", "statuses_valid", "export_summary_valid",
                "import_summary_valid", "procedure_valid", "sensitive_absent",
            ))
            and all(all(side.values()) for side in row["signatures"].values())
            and all(all(side.values()) for side in row["witnesses"].values())
            for row in rows
        )
    )
    summary = {
        "repetitions": len(rows),
        "signed_assertions_verified": sum(
            sum(sum(side.values()) for side in row["signatures"].values()) for row in rows
        ),
        "prf_witness_bindings_verified": sum(
            sum(sum(side.values()) for side in row["witnesses"].values()) for row in rows
        ),
        "functional_continuity_pass_runs": sum(
            row["continuity_status"] == "PASS" for row in rows
        ),
        "source_seed_mismatch_runs": sum(row["source_seed_mismatch"] for row in rows),
        "missing_export_prf_state_runs": sum(row["exported_prf_state_missing"] for row in rows),
    }
    return {
        "evidence_class": "independent-same-provider-browser-roundtrip-recalculation",
        "report_sha256": _sha(report_bytes), "verified": verified,
        "summary": summary, "rows": rows,
    }
