"""Build a private, directly de-identified review artifact.

The output has no Git history or original release manifests. It is a staged
review copy, not an assertion that a public preprint cannot be linked back to
the authors by contextual clues.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "paper/venues/usenixsecurity27/anonymous_artifact"
RELEASE = ROOT / "releases/v0.7.1/passkeytransit-v0.7.1-replication.zip"
RAW_NAMES = {
    "c1_attempts.jsonl": "evidence/20260923T162254713/full/c1_phase7_full_attempts.jsonl",
    "c2_attempts.jsonl": "evidence/20260923T162316380/c2/c2_phase6_attempts.jsonl",
    "c3_sequences.jsonl": "evidence/20260923T162316380/c3/c3_phase6_sequences.jsonl",
    "c3_events.jsonl": "evidence/20260923T162316380/c3/c3_phase6_events.jsonl",
}
SOURCE_FILES = [
    "LICENSE",
    "pyproject.toml",
    "requirements.lock",
    "experiments/protocol_v1.5.json",
    "experiments/protocol_v2.json",
    "experiments/protocol_v2_fenko_roundtrip.json",
    "experiments/protocol_v2_proton_software.json",
    "experiments/cxp_wire_structural/report.json",
    "experiments/phase14_ci_replay/2026-10-20/auditable/prf_migration.json",
    "experiments/v2_exploratory/fenko_provider.json",
    "experiments/v2_roundtrip_exploratory/fenko_roundtrip.json",
    "experiments/phase17_exploratory/proton_cxf_prf.json",
    "interop/proton-cxf-prf/package-lock.json",
    "interop/proton-cxf-prf/run.mjs",
    "paper/current/results_v0.7.json",
    "paper/current/table_c1_route_strata.csv",
    "paper/current/table_c1_estimands.csv",
    "paper/current/table_c1_oracles.csv",
    "paper/current/table_c2_mutations.csv",
    "paper/current/table_c3_faults.csv",
    "paper/venues/usenixsecurity27/official_pdf/main.tex",
    "paper/venues/usenixsecurity27/official_pdf/usenix.sty",
    "src/passkeytransit/cxp_wire_probe.py",
    "tools/run_cxp_wire_probe.py",
    "tools/run_proton_cxf_prf.py",
    "tools/verify_phase14_public_transcript.py",
    "tools/verify_proton_public_report.py",
    "tools/verify_provider_reports.py",
    "tools/verify_anonymous_artifact.py",
]
DIRECT_IDENTIFIERS = [
    re.compile(rb"(?i)github\.com/fedequark(?:/|\b)"),
    re.compile(rb"(?i)(?<![A-Za-z0-9])fedep(?![A-Za-z0-9])"),
    re.compile(rb"(?i)C:[/\\]Users[/\\]"),
    re.compile(rb"(?i)codex/peer-review-revision"),
]
EMAIL = re.compile(rb"(?i)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _jsonl_without_revision(data: bytes) -> bytes:
    output = io.StringIO()
    for line in data.splitlines():
        row = json.loads(line)
        row.pop("source_commit", None)
        output.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    return output.getvalue().encode("utf-8")


def build() -> Path:
    files: dict[str, bytes] = {}
    for path in SOURCE_FILES:
        files[path] = (ROOT / path).read_bytes()
    for source in sorted((ROOT / "src/passkeytransit").glob("*.py")):
        files[source.relative_to(ROOT).as_posix()] = source.read_bytes()
    for source in sorted((ROOT / "tests").glob("test_*.py")):
        files[source.relative_to(ROOT).as_posix()] = source.read_bytes()
    with zipfile.ZipFile(RELEASE) as original:
        for output, source in RAW_NAMES.items():
            files[f"data/raw/{output}"] = _jsonl_without_revision(original.read(source))
    files["README.md"] = (
        "# Anonymous staged review artifact\n\n"
        "Contains synthetic C1/C2/C3 rows, result tables, selected public "
        "browser and provider reports, protocols, source, and a CXP draft "
        "structure probe. Git history, commit IDs in raw rows, "
        "and original provenance manifests were intentionally omitted.\n\n"
        "Run python verify.py after extraction. With dependencies installed, "
        "run python tools/verify_provider_reports.py, "
        "python tools/run_cxp_wire_probe.py and "
        "PYTHONPATH=src python -m pytest tests/test_cxp_wire_probe.py "
        "(set PYTHONPATH appropriately on Windows).\n\n"
        "This package supports internal review of synthetic controls and "
        "public signature reports. Provider replay ZIPs and CI provenance "
        "are not in this staged copy. It is not yet a complete submission artifact. "
        "No independent review or external provider interoperability is claimed.\n"
    ).encode()
    files["verify.py"] = (ROOT / "tools/verify_anonymous_artifact.py").read_bytes()
    for name, data in files.items():
        for pattern in DIRECT_IDENTIFIERS:
            if pattern.search(data):
                raise ValueError(f"direct identifier in {name}: {pattern.pattern!r}")
        for match in EMAIL.findall(data):
            if not match.lower().endswith((b"@example.test", b"@example.com")):
                raise ValueError(f"email-like value in {name}: {match!r}")
    manifest = {
        "artifact": "passkeytransit-anonymous-staging-v1",
        "scope": "synthetic-campaign-public-provider-reports-and-cxp-structure",
        "files": {name: _sha(data) for name, data in sorted(files.items())},
        "source_release_raw_rows": "v0.7.1 synthetic evidence, source_commit field removed",
        "limitations": [
            "not a complete provider replay package",
            "contextual linkage to an already public project cannot be ruled out",
            "no third-party replication claimed",
        ],
    }
    files["manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / "passkeytransit-anonymous-staging.zip"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    audit = {
        "archive_sha256": _sha(target.read_bytes()),
        "file_count": len(files),
        "raw_row_counts": {name: len(files[f"data/raw/{name}"].splitlines()) for name in RAW_NAMES},
        "direct_identifier_scan": "PASS",
        "distribution": "private-staging-only",
        "limitations": manifest["limitations"],
    }
    (OUT / "audit.json").write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


if __name__ == "__main__":
    print(build())
