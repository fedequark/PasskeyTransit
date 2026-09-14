from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SENSITIVE_NAMES = {"private_key", "privatekey", "secret", "token", "password", "key"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tracked_files(project_root: Path) -> list[Path]:
    output = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=project_root, text=False
    )
    return [project_root / item.decode("utf-8") for item in output.split(b"\0") if item]


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


def build_release(
    project_root: Path,
    evidence_roots: list[Path],
    external_result: Path,
    oracle_report: Path,
    output_dir: Path,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / "passkeytransit-v0.2.0-replication.zip"
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

    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=project_root, text=True
    ).strip()
    dirty = bool(
        subprocess.check_output(["git", "status", "--porcelain"], cwd=project_root, text=True).strip()
    )
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
            "release": "v0.2.0",
            "source_commit": commit,
            "entries": entry_hashes,
            "reproduce": "Extract source/, run ./research.ps1 setup, test, phase6, phase7, phase8, phase9, phase11 and oracle-audit.",
        }
        _zip_write(archive, "MANIFEST.json", (json.dumps(internal, indent=2) + "\n").encode())

    manifest = {
        "release": "v0.2.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_commit": commit,
        "source_dirty": False,
        "archive": archive_path.name,
        "archive_sha256": _sha(archive_path.read_bytes()),
        "archive_bytes": archive_path.stat().st_size,
        "entry_count": len(entry_hashes) + 1,
        "privacy_audit": audit,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def verify_release(archive_path: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    archive_hash_ok = _sha(archive_path.read_bytes()) == manifest["archive_sha256"]
    mismatches: list[str] = []
    with zipfile.ZipFile(archive_path) as archive:
        internal = json.loads(archive.read("MANIFEST.json"))
        for name, expected in internal["entries"].items():
            if _sha(archive.read(name)) != expected:
                mismatches.append(name)
    return {
        "archive_sha256_ok": archive_hash_ok,
        "entry_hash_mismatches": mismatches,
        "verified": archive_hash_ok and not mismatches,
    }
