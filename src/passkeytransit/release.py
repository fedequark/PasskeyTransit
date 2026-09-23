from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import __version__
from .analysis import RESULTS_FILENAME, run_analysis
from .browser_campaign import summarize_browser_c1
from .evidence import audit_browser_evidence, audit_browser_evidence_payloads
from .robustness import summarize_c2_rows, summarize_c3_rows


SENSITIVE_NAMES = {"private_key", "privatekey", "secret", "token", "password", "key"}
STALE_GENERATED_PREFIXES = ("paper/current/", "paper/legacy/", "releases/", "reviews/")
RELEASE_ID = f"v{__version__}"
ARCHIVE_NAME = f"passkeytransit-{RELEASE_ID}-replication.zip"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tracked_files(project_root: Path) -> list[Path]:
    output = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=project_root, text=False
    )
    return [
        project_root / item.decode("utf-8") for item in output.split(b"\0")
        if item and not item.decode("utf-8").replace("\\", "/").startswith(STALE_GENERATED_PREFIXES)
    ]


def _tracked_tree_dirty(project_root: Path) -> bool:
    unstaged = subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=project_root)
    staged = subprocess.run(["git", "diff", "--cached", "--quiet", "HEAD", "--"], cwd=project_root)
    return unstaged.returncode != 0 or staged.returncode != 0


def _analysis_lineage_missing(analysis_manifest: dict[str, Any], hashes: set[str]) -> list[str]:
    return [
        f"{section}.{name}" for section in ("input_hashes", "output_hashes")
        for name, digest in analysis_manifest.get(section, {}).items() if digest not in hashes
    ]


def _scan_json_value(value: Any, path: str, findings: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).replace("-", "_").lower()
            if normalized in SENSITIVE_NAMES:
                findings.append(f"{path}.{key}")
            _scan_json_value(child, f"{path}.{key}", findings)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_json_value(child, f"{path}[{index}]", findings)


def privacy_audit(paths: Iterable[Path]) -> dict[str, Any]:
    findings: list[str] = []
    inspected = 0
    for path in paths:
        if path.suffix not in {".json", ".jsonl"}:
            continue
        if path.suffix == ".json":
            inspected += 1
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                findings.append(f"{path}:invalid-json")
            else:
                _scan_json_value(value, str(path), findings)
            continue
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                inspected += 1
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    findings.append(f"{path}:{line_number}:invalid-json")
                    continue
                _scan_json_value(value, f"{path}:{line_number}", findings)
    return {
        "json_records_inspected": inspected,
        "sensitive_field_findings": findings,
        "passed": not findings,
        "scope": "field-name audit; synthetic identifiers and evidence hashes are retained",
    }


def _zip_write(archive: zipfile.ZipFile, arcname: str, data: bytes) -> str:
    info = zipfile.ZipInfo(arcname, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data, compresslevel=9)
    return _sha(data)


def _entry_by_basename(names: Iterable[str], basename: str) -> str:
    matches = [name for name in names if Path(name).name == basename]
    if len(matches) != 1:
        raise ValueError(f"release requires exactly one {basename}; found {len(matches)}")
    return matches[0]


def _jsonl(payload: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in payload.decode("utf-8").splitlines() if line.strip()]


def _verify_release_derivations(archive: zipfile.ZipFile, names: Iterable[str]) -> dict[str, Any]:
    entries = list(names)
    protocol_name = _entry_by_basename(entries, "protocol_v1.5.json")
    protocol = json.loads(archive.read(protocol_name))
    if not str(protocol.get("protocol_id", "")).endswith("v1.5"):
        raise ValueError("release derivation audit requires protocol v1.5")

    summary_pairs: list[tuple[str, dict[str, Any]]] = []
    for mode in ("calibration", "full"):
        raw_name = _entry_by_basename(entries, f"c1_phase7_{mode}_attempts.jsonl")
        summary_pairs.append((
            f"c1-{mode}",
            summarize_browser_c1(_jsonl(archive.read(raw_name)), protocol, mode),
        ))
    c2_rows = _jsonl(archive.read(_entry_by_basename(entries, "c2_phase6_attempts.jsonl")))
    summary_pairs.append(("c2", summarize_c2_rows(c2_rows, protocol)))
    c3_sequences = _jsonl(archive.read(_entry_by_basename(entries, "c3_phase6_sequences.jsonl")))
    c3_events = _jsonl(archive.read(_entry_by_basename(entries, "c3_phase6_events.jsonl")))
    summary_pairs.append(("c3", summarize_c3_rows(c3_sequences, c3_events, protocol)))

    summary_files = {
        "c1-calibration": "c1_phase7_calibration_summary.json",
        "c1-full": "c1_phase7_full_summary.json",
        "c2": "c2_phase6_summary.json",
        "c3": "c3_phase6_summary.json",
    }
    for label, reproduced in summary_pairs:
        recorded = json.loads(archive.read(_entry_by_basename(entries, summary_files[label])))
        if reproduced != recorded:
            raise ValueError(f"raw evidence does not reproduce {summary_files[label]}")

    required_inputs = {
        "phase7_summary": "c1_phase7_full_summary.json",
        "phase7_manifest": "c1_phase7_full_manifest.json",
        "c2_summary": "c2_phase6_summary.json",
        "c2_manifest": "c2_phase6_manifest.json",
        "c3_summary": "c3_phase6_summary.json",
        "c3_manifest": "c3_phase6_manifest.json",
        "interop_path": "interop_result.json",
        "external_path": "bitwarden_cxf_interop.json",
        "oracle_report_path": "oracle_capabilities.json",
    }
    with tempfile.TemporaryDirectory(prefix="passkeytransit-release-audit-") as temporary:
        root = Path(temporary)
        paths: dict[str, Path] = {}
        for key, basename in required_inputs.items():
            path = root / basename
            path.write_bytes(archive.read(_entry_by_basename(entries, basename)))
            paths[key] = path
        output = root / "analysis"
        run_analysis(output_dir=output, **paths)
        reproduced_outputs = (
            RESULTS_FILENAME,
            "MANUSCRIPT.md",
            "table_c1_estimands.csv",
            "table_c1_route_strata.csv",
            "table_c1_oracles.csv",
            "table_c2_mutations.csv",
            "table_c3_faults.csv",
        )
        for basename in reproduced_outputs:
            if output.joinpath(basename).read_bytes() != archive.read(
                _entry_by_basename(entries, basename)
            ):
                raise ValueError(f"summaries do not reproduce published output {basename}")
    return {
        "protocol_id": protocol["protocol_id"],
        "raw_summaries_recomputed": [label for label, _ in summary_pairs],
        "published_outputs_reproduced": list(reproduced_outputs),
        "passed": True,
    }


def build_release(
    project_root: Path,
    evidence_roots: list[Path],
    external_result: Path,
    oracle_report: Path,
    output_dir: Path,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / ARCHIVE_NAME
    manifest_path = output_dir / "release_manifest.json"
    if archive_path.exists() or manifest_path.exists():
        raise FileExistsError("release output is immutable; remove or choose a new output directory")

    evidence_files = sorted(
        [path for root in evidence_roots for path in root.rglob("*") if path.is_file()]
        + [external_result, oracle_report],
        key=lambda path: str(path),
    )
    audit = privacy_audit(evidence_files)
    if not audit["passed"]:
        raise ValueError(f"privacy audit failed: {audit['sensitive_field_findings'][:3]}")
    evidence_hashes = {_sha(path.read_bytes()) for path in evidence_files}
    analysis_manifests = [path for path in evidence_files if path.name == "analysis_manifest.json"]
    if len(analysis_manifests) != 1:
        raise ValueError("release requires exactly one canonical analysis_manifest.json")
    missing = _analysis_lineage_missing(json.loads(analysis_manifests[0].read_text(encoding="utf-8")), evidence_hashes)
    if missing:
        raise ValueError(f"analysis lineage has unresolved hashes: {missing}")
    browser_audit = audit_browser_evidence(evidence_files)

    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=project_root, text=True
    ).strip()
    dirty = _tracked_tree_dirty(project_root)
    if dirty:
        raise ValueError("release must be built from a clean source tree")

    entry_hashes: dict[str, str] = {}
    with zipfile.ZipFile(archive_path, "x") as archive:
        for path in sorted(_tracked_files(project_root), key=lambda item: item.as_posix()):
            relative = path.relative_to(project_root).as_posix()
            entry_hashes[f"source/{relative}"] = _zip_write(
                archive, f"source/{relative}", path.read_bytes()
            )
        for root in evidence_roots:
            label = root.name
            for path in sorted((item for item in root.rglob("*") if item.is_file()), key=str):
                arcname = f"evidence/{label}/{path.relative_to(root).as_posix()}"
                entry_hashes[arcname] = _zip_write(archive, arcname, path.read_bytes())
        for path in (external_result, oracle_report):
            arcname = f"evidence/phase11-12/{path.name}"
            entry_hashes[arcname] = _zip_write(archive, arcname, path.read_bytes())
        internal = {
            "release": RELEASE_ID,
            "source_commit": commit,
            "entries": entry_hashes,
            "reproduce": "Extract source/, run ./research.ps1 setup, test, phase6, phase7, phase8, phase9, phase11 and oracle-audit.",
        }
        _zip_write(archive, "MANIFEST.json", (json.dumps(internal, indent=2) + "\n").encode())

    with zipfile.ZipFile(archive_path) as archive:
        derivation_audit = _verify_release_derivations(archive, entry_hashes)

    manifest = {
        "release": RELEASE_ID,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_commit": commit,
        "source_dirty": False,
        "archive": archive_path.name,
        "archive_sha256": _sha(archive_path.read_bytes()),
        "archive_bytes": archive_path.stat().st_size,
        "entry_count": len(entry_hashes) + 1,
        "privacy_audit": audit,
        "browser_transcript_audit": browser_audit,
        "derivation_audit": derivation_audit,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def verify_release(archive_path: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    archive_hash_ok = _sha(archive_path.read_bytes()) == manifest["archive_sha256"]
    mismatches: list[str] = []
    with zipfile.ZipFile(archive_path) as archive:
        archive_names = archive.namelist()
        duplicate_names = sorted({name for name in archive_names if archive_names.count(name) > 1})
        mismatches.extend(f"duplicate-entry:{name}" for name in duplicate_names)
        internal = json.loads(archive.read("MANIFEST.json"))
        expected_names = set(internal["entries"]) | {"MANIFEST.json"}
        actual_names = set(archive_names)
        mismatches.extend(f"undeclared-entry:{name}" for name in sorted(actual_names - expected_names))
        mismatches.extend(f"missing-entry:{name}" for name in sorted(expected_names - actual_names))
        for field in ("release", "source_commit"):
            if field in manifest and manifest[field] != internal.get(field):
                mismatches.append(f"manifest-{field}-mismatch")
        if "archive" in manifest and manifest["archive"] != archive_path.name:
            mismatches.append("manifest-archive-name-mismatch")
        for name, expected in internal["entries"].items():
            if _sha(archive.read(name)) != expected:
                mismatches.append(name)
        analysis_names = [
            name for name in internal["entries"]
            if name.startswith("evidence/") and name.endswith("/analysis_manifest.json")
        ]
        if len(analysis_names) != 1:
            mismatches.append("analysis-manifest-count")
        else:
            analysis = json.loads(archive.read(analysis_names[0]))
            missing = _analysis_lineage_missing(analysis, set(internal["entries"].values()))
            mismatches.extend(missing)
        browser_names = [
            name for name in internal["entries"]
            if Path(name).name.startswith("c1_phase7_")
            and Path(name).name.endswith("_attempts.jsonl")
        ]
        browser_audit: dict[str, Any] = {"passed": None, "reason": "no browser evidence"}
        if browser_names:
            try:
                browser_audit = audit_browser_evidence_payloads(
                    (name, archive.read(name)) for name in browser_names
                )
            except (ValueError, KeyError, json.JSONDecodeError) as exc:
                browser_audit = {"passed": False, "error": str(exc)}
                mismatches.append("browser-transcript-audit")
        requires_derivation_audit = any(
            Path(name).name == "protocol_v1.5.json" for name in internal["entries"]
        )
        derivation_audit: dict[str, Any] = {"passed": None, "reason": "pre-v1.5 release"}
        if requires_derivation_audit:
            try:
                derivation_audit = _verify_release_derivations(archive, internal["entries"])
            except (ValueError, KeyError, json.JSONDecodeError) as exc:
                derivation_audit = {"passed": False, "error": str(exc)}
                mismatches.append("derivation-audit")
    return {
        "archive_sha256_ok": archive_hash_ok,
        "entry_hash_mismatches": mismatches,
        "browser_transcript_audit": browser_audit,
        "derivation_audit": derivation_audit,
        "verified": archive_hash_ok and not mismatches,
    }
