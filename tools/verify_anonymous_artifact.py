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
        "external_cxp_parser_scope": parser_report["scope"],
        "second_cxp_parser_scope": go_report["scope"],
        "cxp_parser_comparison_recomputed": True,
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
