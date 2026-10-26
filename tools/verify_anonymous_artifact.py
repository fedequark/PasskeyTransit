"""Verify hashes and recompute anonymous C1 route-by-stratum counts."""

from __future__ import annotations

import csv
import hashlib
import json
import io
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path


def verify(root: Path) -> dict[str, object]:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    for name, expected in manifest["files"].items():
        source = root / name
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise ValueError(f"missing or modified artifact member: {name}")
    rp_control = json.loads((root / "experiments/cxporter_cxp_open/poc2_rp_control.json").read_text(encoding="utf-8"))
    rp_probe = root / "interop/cxp_poc2_cross_probe/pt-rp-control.ts"
    if rp_control["status"] != "SAME_CODEBASE_RP_CONTROL_PASS" or rp_control["probe_sha256"] != hashlib.sha256(rp_probe.read_bytes()).hexdigest():
        raise ValueError("PoC RP control source or status differs")
    if len(rp_control["cases"]) != 4 or any(not c["target_login_after"] or c["imported_passkeys"] != 1 for c in rp_control["cases"]):
        raise ValueError("PoC RP control result differs")
    if (root / "experiments/cxporter_cxp_open/ci/40363074055/poc2_rp_control.json").read_bytes() != (root / "experiments/cxporter_cxp_open/poc2_rp_control.json").read_bytes():
        raise ValueError("PoC RP control CI and local reports differ")
    replay_bytes = (root / "data/replay/phase14-original.zip").read_bytes()
    with zipfile.ZipFile(io.BytesIO(replay_bytes)) as replay:
        members = replay.namelist()
        if replay.testzip() is not None or len(members) != 2:
            raise ValueError("invalid Phase 14 replay archive")
        expected_reports = {"cross_runtime_cxp.json", "prf_migration.json"}
        if {name.rsplit("/", 1)[-1] for name in members} != expected_reports:
            raise ValueError("unexpected Phase 14 replay members")
        for member in members:
            basename = member.rsplit("/", 1)[-1]
            report = root / "experiments/phase14_ci_replay/2026-10-20/auditable" / basename
            if replay.read(member) != report.read_bytes():
                raise ValueError(f"Phase 14 replay report mismatch: {basename}")

    provider_bytes = (root / "data/replay/provider-local.zip").read_bytes()
    with zipfile.ZipFile(io.BytesIO(provider_bytes)) as replay:
        if replay.testzip() is not None:
            raise ValueError("invalid local provider replay archive")
        provider_manifest = json.loads(replay.read("manifest.json"))
        if set(replay.namelist()) != set(provider_manifest["files"]) | {"manifest.json"}:
            raise ValueError("unexpected local provider replay members")
        for member, expected in provider_manifest["files"].items():
            if hashlib.sha256(replay.read(member)).hexdigest() != expected:
                raise ValueError(f"local provider replay member mismatch: {member}")

    for provider, reports in {
        "fenko": ("fenko_provider.json", "fenko_roundtrip.json"),
        "proton": ("proton_cxf_prf.json",),
    }.items():
        ci_bytes = (root / f"data/replay/{provider}-ci-original.zip").read_bytes()
        with zipfile.ZipFile(io.BytesIO(ci_bytes)) as replay:
            if replay.testzip() is not None or set(replay.namelist()) != set(reports):
                raise ValueError(f"invalid {provider} CI replay archive")
            for report in reports:
                if replay.read(report) != (root / "data/replay/ci" / report).read_bytes():
                    raise ValueError(f"{provider} CI report differs from original ZIP: {report}")
    cxporter_zip = (root / "data/replay/cxporter-ci-original.zip").read_bytes()
    with zipfile.ZipFile(io.BytesIO(cxporter_zip)) as replay:
        if replay.testzip() is not None or replay.namelist() != ["report.json"]:
            raise ValueError("invalid cxporter CI replay archive")
        if replay.read("report.json") != (root / "data/replay/ci/cxporter_cxp_report.json").read_bytes():
            raise ValueError("cxporter CI report differs from original ZIP")
    cross_zip = (root / "data/replay/cxp-poc2-cross-ci-original.zip").read_bytes()
    with zipfile.ZipFile(io.BytesIO(cross_zip)) as replay:
        if replay.testzip() is not None or replay.namelist() != ["cross_import_rejection.json"]:
            raise ValueError("invalid cross-implementation CI replay archive")
        if replay.read("cross_import_rejection.json") != (
            root / "data/replay/ci/cxp_poc2_cross_report.json"
        ).read_bytes():
            raise ValueError("cross-implementation CI report differs from original ZIP")

    sys.path.insert(0, str(root / "src"))
    from passkeytransit.fenko_verify import verify_fenko_report
    from passkeytransit.fenko_roundtrip_verify import verify_fenko_roundtrip

    ci_fenko = verify_fenko_report(
        root / "data/replay/ci/fenko_provider.json", root / "experiments/protocol_v2.json"
    )["summary"]
    ci_roundtrip = verify_fenko_roundtrip(
        root / "data/replay/ci/fenko_roundtrip.json",
        root / "experiments/protocol_v2_fenko_roundtrip.json",
    )["summary"]
    sys.path.insert(0, str(root / "tools"))
    from verify_proton_public_report import verify_report as verify_proton_public

    ci_proton = verify_proton_public(json.loads(
        (root / "data/replay/ci/proton_cxf_prf.json").read_text(encoding="utf-8")
    ))
    ci_counts = (
        ci_fenko["signed_assertions_verified"], ci_fenko["prf_witness_bindings_verified"],
        ci_roundtrip["signed_assertions_verified"], ci_roundtrip["prf_witness_bindings_verified"],
        ci_proton["public_signatures_verified"], ci_proton["public_prf_digests_verified"],
    )
    if ci_counts != (16, 6, 24, 12, 12, 12):
        raise ValueError(f"unexpected provider CI public verifier counts: {ci_counts}")
    from verify_cxporter_cxp_public_report import verify_report as verify_cxporter_public

    cxporter_local = verify_cxporter_public(json.loads(
        (root / "experiments/cxporter_cxp_open/report.json").read_text(encoding="utf-8")
    ))
    cxporter_ci = verify_cxporter_public(json.loads(
        (root / "data/replay/ci/cxporter_cxp_report.json").read_text(encoding="utf-8")
    ))
    if cxporter_local["public_signatures_verified"] != 8 or cxporter_ci["public_signatures_verified"] != 8:
        raise ValueError("unexpected cxporter signature counts")
    from verify_cxp_poc2_cross_report import verify as verify_cross

    cross_local = verify_cross(json.loads(
        (root / "experiments/cxporter_cxp_open/cross_import_rejection.json").read_text(encoding="utf-8")
    ))
    cross_ci = verify_cross(json.loads(
        (root / "data/replay/ci/cxp_poc2_cross_report.json").read_text(encoding="utf-8")
    ))
    if cross_local["cross_import_expected_rejections"] != 2 or cross_ci["cross_import_expected_rejections"] != 2:
        raise ValueError("unexpected cross-import control counts")
    from verify_cxp_public_vector import verify as verify_public_vector, verify_replay

    vector = verify_public_vector(root / "experiments/cxporter_cxp_open/vectors/cxporter-poc2-v1.json")
    vector_ci = json.loads((root / "experiments/cxporter_cxp_open/ci/40359254321/public_vector_replay.json").read_text())
    fresh_ci = json.loads((root / "experiments/cxporter_cxp_open/ci/40359254321/fresh_vector_replay.json").read_text())
    verify_replay(vector_ci, retained=True)
    verify_replay(fresh_ci, retained=False)
    if fresh_ci["archive_sha256"] == vector_ci["archive_sha256"]:
        raise ValueError("fresh exporter replay reused the retained ciphertext")
    from verify_cxp_index_control import verify as verify_index_control

    index_control = verify_index_control(root, root / "experiments/cxporter_cxp_open/index_control.json")
    index_control_ci = verify_index_control(root, root / "experiments/cxporter_cxp_open/ci/40361395703/index_control.json")
    index_local_report = json.loads((root / "experiments/cxporter_cxp_open/index_control.json").read_text())
    index_ci_report = json.loads((root / "experiments/cxporter_cxp_open/ci/40361395703/index_control.json").read_text())
    if index_local_report["observation"]["transformed_archive_sha256"] == index_ci_report["observation"]["transformed_archive_sha256"]:
        raise ValueError("index CI control reused the local transformed archive")

    parser_report = json.loads((root / "experiments/cxp_external_schema/runtime_report.json").read_text())
    if parser_report.get("provider_interoperability") != "NOT_EVALUABLE":
        raise ValueError("external CXP parser report overclaims interoperability")
    go_report = json.loads((root / "experiments/cxp_external_schema/go_runtime_report.json").read_text())
    if go_report.get("request_fields_dropped_on_roundtrip") != ["mode"]:
        raise ValueError("unexpected Go CXP parser result")
    if go_report.get("provider_interoperability") != "NOT_EVALUABLE":
        raise ValueError("Go CXP parser report overclaims interoperability")
    sys.path.insert(0, str(root / "tools"))
    from compare_cxp_type_parsers import compare

    saved_comparison = json.loads((root / "experiments/cxp_external_schema/comparison.json").read_text())
    if saved_comparison != compare():
        raise ValueError("CXP parser comparison differs from the two reports")
    from verify_cxp_zip_jwe_reports import verify as verify_zip_jwe

    zip_jwe_result = verify_zip_jwe(root)
    from verify_jose_hpke_go_interop import verify as verify_jose_hpke

    jose_result = verify_jose_hpke(root)
    from verify_cxp_jose_zip_go import verify as verify_cxp_jose_zip

    cxp_jose_result = verify_cxp_jose_zip(root)
    from verify_proton_cxp_wire_reports import verify as verify_proton_cxp_wire

    proton_cxp_result = verify_proton_cxp_wire(root)

    observed: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    attempts = 0
    with (root / "data/raw/c1_attempts.jsonl").open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if "source_commit" in row:
                raise ValueError("raw row retains project commit")
            counts = observed[row["route_id"], row["feature_stratum"]]
            counts["attempts"] += 1
            counts["imported" if row["execution_status"] == "IMPORTED" else "rejected"] += 1
            status = row["semantic_class"]
            key = {
                "PASS": "semantic_pass",
                "DEGRADED_VISIBLE": "degraded_visible",
                "DEGRADED_SILENT": "degraded_silent",
                "NOT_EVALUABLE": "not_evaluable",
                "NOT_APPLICABLE": None,
            }[status]
            if key:
                counts[key] += 1
            counts["false_reassurance"] += int(bool(row["false_reassurance"]))
            counts["representation_loss"] += int(bool(row["login_with_nonexecuted_representation_loss"]))
            attempts += 1

    columns = (
        "attempts", "imported", "rejected", "semantic_pass", "degraded_visible",
        "degraded_silent", "not_evaluable", "false_reassurance", "representation_loss",
    )
    with (root / "paper/current/table_c1_route_strata.csv").open(
        encoding="utf-8", newline=""
    ) as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != 96 or len(observed) != 96:
        raise ValueError("C1 matrix does not have 96 route-by-stratum cells")
    for row in rows:
        key = row["route_id"], row["feature_stratum"]
        if key not in observed:
            raise ValueError(f"missing C1 group: {key}")
        for column in columns:
            if observed[key][column] != int(row[column]):
                raise ValueError(f"C1 mismatch in {key} {column}")
    totals = Counter()
    for counts in observed.values():
        totals.update(counts)
    expected = {
        "attempts": 6144, "imported": 5120, "rejected": 1024,
        "semantic_pass": 2304, "degraded_visible": 960,
        "degraded_silent": 1344, "not_evaluable": 512,
        "false_reassurance": 512, "representation_loss": 1792,
    }
    for key, value in expected.items():
        if totals[key] != value:
            raise ValueError(f"C1 total mismatch: {key}")
    other_counts = {}
    for name, expected_count in (
        ("c2_attempts.jsonl", 80), ("c3_sequences.jsonl", 960),
        ("c3_events.jsonl", 1920),
    ):
        count = sum(1 for _ in (root / "data/raw" / name).open(encoding="utf-8"))
        if count != expected_count:
            raise ValueError(f"unexpected {name} row count")
        other_counts[name] = count
    return {
        "status": "PASS",
        "hashed_members": len(manifest["files"]),
        "phase14_replay_reports_byte_equal": 2,
        "provider_replay_hashed_members": len(provider_manifest["files"]),
        "provider_ci_original_zips_checked": 2,
        "cxporter_ci_original_zip_checked": True,
        "cxporter_local_signatures_verified": cxporter_local["public_signatures_verified"],
        "cxporter_ci_signatures_verified": cxporter_ci["public_signatures_verified"],
        "cxp_poc2_cross_ci_original_zip_checked": True,
        "cxp_poc2_cross_local_rejections": cross_local["cross_import_expected_rejections"],
        "cxp_poc2_cross_ci_rejections": cross_ci["cross_import_expected_rejections"],
        "cxp_public_vector_jwe_files": vector["jwe_files"],
        "cxp_public_vector_ci_replays": 2,
        "cxp_index_control_local": index_control["status"],
        "cxp_index_control_ci": index_control_ci["status"],
        "provider_ci_report_byte_matches": 3,
        "provider_ci_fenko_signatures_verified": ci_counts[0] + ci_counts[2],
        "provider_ci_fenko_prf_bindings_verified": ci_counts[1] + ci_counts[3],
        "provider_ci_proton_signatures_verified": ci_counts[4],
        "provider_ci_proton_prf_bindings_verified": ci_counts[5],
        "external_cxp_parser_scope": parser_report["scope"],
        "second_cxp_parser_scope": go_report["scope"],
        "cxp_parser_comparison_recomputed": True,
        "cxp_zip_jwe_profile_controls": zip_jwe_result["local_controls"],
        "cxp_zip_jwe_cross_runtime_controls": zip_jwe_result["cross_runtime_controls"],
        "external_jose_hpke_crypto_controls": jose_result["controls"],
        "cxp_jose_zip_external_crypto_controls": cxp_jose_result["controls"],
        "proton_cxp_basic_controls": proton_cxp_result["basic_controls"],
        "proton_cxp_passkey_controls": proton_cxp_result["passkey_controls"],
        "proton_cxp_reverse_controls": proton_cxp_result["reverse_controls"],
        "proton_cxp_signed_assertions_verified": proton_cxp_result["signed_assertions_verified"],
        "c1_attempts": attempts,
        "c1_groups": len(observed),
        "c1_totals": expected,
        "other_row_counts": other_counts,
        "scope": manifest["scope"],
    }


def main() -> None:
    here = Path(__file__).resolve()
    root = here.parent if (here.parent / "manifest.json").exists() else here.parents[1]
    print(json.dumps(verify(root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
