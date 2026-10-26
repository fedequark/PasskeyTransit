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
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "paper/venues/usenixsecurity27/anonymous_artifact"
RELEASE = ROOT / "releases/v0.7.1/passkeytransit-v0.7.1-replication.zip"
PHASE14_DIR = ROOT / "experiments/phase14_ci_replay/2026-10-20/auditable"
PHASE14_ARCHIVE = PHASE14_DIR / "phase14-auditable-39446248808.zip"
PROVIDER_ARCHIVE = ROOT / "experiments/provider_replays/2026-10-26/provider-replay-local.zip"
PROVIDER_CI = ROOT / "experiments/provider_replays/2026-10-26/ci/40344602464"
PROVIDER_CI_REPORTS = {
    "fenko": ("fenko_provider.json", "fenko_roundtrip.json"),
    "proton": ("proton_cxf_prf.json",),
}
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
    "experiments/cxp_external_schema/bitwarden_protocol_snapshot.json",
    "experiments/cxp_external_schema/report.json",
    "experiments/cxp_external_schema/fixture.json",
    "experiments/cxp_external_schema/runtime_report.json",
    "experiments/cxp_external_schema/go_runtime_report.json",
    "experiments/cxp_external_schema/comparison.json",
    "experiments/cxp_zip_jwe_experimental/report.json",
    "experiments/cxp_zip_jwe_experimental/cross_runtime.json",
    "experiments/jose_hpke_go_interop/report.json",
    "experiments/cxp_jose_zip_go/report.json",
    "experiments/proton_cxp_wire/proton-cxp-wire-report.json",
    "experiments/proton_cxp_wire/proton-cxp-passkey-report.json",
    "experiments/proton_cxp_wire/proton-cxp-reverse-report.json",
    "interop/bitwarden_cxp_types/Cargo.lock",
    "interop/bitwarden_cxp_types/Cargo.toml",
    "interop/bitwarden_cxp_types/src/main.rs",
    "interop/go_cxp_types/go.mod",
    "interop/go_cxp_types/main.go",
    "interop/node_cxp_zip_jwe.mjs",
    "interop/jose_hpke_go/go.mod",
    "interop/jose_hpke_go/go.sum",
    "interop/jose_hpke_go/main.go",
    "interop/proton_cxp_wire/Cargo.toml",
    "interop/proton_cxp_wire/Cargo.lock",
    "interop/proton_cxp_wire/src/main.rs",
    "docs/CXP_ZIP_JWE_EXPERIMENT.md",
    "docs/JOSE_HPKE_EXTERNAL_CRYPTO.md",
    "docs/CXP_JOSE_ZIP_EXPERIMENT.md",
    "experiments/phase14_ci_replay/2026-10-20/auditable/cross_runtime_cxp.json",
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
    "tools/run_cxp_schema_gap.py",
    "tools/verify_cxp_runtime_report.py",
    "tools/verify_go_cxp_runtime_report.py",
    "tools/compare_cxp_type_parsers.py",
    "tools/run_cxp_zip_jwe_profile.py",
    "tools/run_cxp_zip_jwe_cross_runtime.py",
    "tools/verify_cxp_zip_jwe_reports.py",
    "tools/run_jose_hpke_go_interop.py",
    "tools/verify_jose_hpke_go_interop.py",
    "tools/run_cxp_jose_zip_go.py",
    "tools/verify_cxp_jose_zip_go.py",
    "tools/run_proton_cxp_wire.py",
    "tools/run_proton_cxp_passkey.py",
    "tools/run_proton_cxp_reverse.py",
    "tools/verify_proton_cxp_wire_reports.py",
    "tools/run_proton_cxf_prf.py",
    "tools/verify_phase14_public_transcript.py",
    "tools/verify_proton_public_report.py",
    "tools/verify_provider_reports.py",
    "tools/verify_anonymous_artifact.py",
]
RAW_BYTE_FILES = {
    "experiments/phase14_ci_replay/2026-10-20/auditable/cross_runtime_cxp.json",
    "experiments/phase14_ci_replay/2026-10-20/auditable/prf_migration.json",
}
DIRECT_IDENTIFIERS = [
    re.compile(rb"(?i)github\.com/fedequark(?:/|\b)"),
    re.compile(rb"(?i)(?<![A-Za-z0-9])fedep(?![A-Za-z0-9])"),
    re.compile(rb"(?i)C:[/\\]Users[/\\]"),
    re.compile(rb"(?i)codex/peer-review-revision"),
]
EMAIL = re.compile(rb"(?i)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _source_bytes(name: str) -> bytes:
    data = (ROOT / name).read_bytes()
    return data if name in RAW_BYTE_FILES else data.replace(b"\r\n", b"\n")


def _python_sources(directory: str) -> list[str]:
    # In a working tree, staged review must not silently absorb untracked tests.
    # In a source archive without .git, every extracted file is from Git.
    if (ROOT / ".git").exists():
        result = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "--cached", "--", directory],
            check=True, capture_output=True, text=True,
        )
        return sorted(name for name in result.stdout.splitlines()
                      if name.endswith(".py") and
                      (directory != "tests" or Path(name).name.startswith("test_")))
    return sorted(path.relative_to(ROOT).as_posix()
                  for path in (ROOT / directory).glob("test_*.py" if directory == "tests" else "*.py"))


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
        files[path] = _source_bytes(path)
    for source in _python_sources("src/passkeytransit") + _python_sources("tests"):
        files[source] = _source_bytes(source)
    with zipfile.ZipFile(RELEASE) as original:
        for output, source in RAW_NAMES.items():
            files[f"data/raw/{output}"] = _jsonl_without_revision(original.read(source))
    # Preserve the original replay bytes. Its GitHub run mapping stays in the
    # private sidecar, outside the review archive.
    phase14_bytes = PHASE14_ARCHIVE.read_bytes()
    phase14_provenance = json.loads((PHASE14_DIR / "provenance.json").read_text(encoding="utf-8"))
    if _sha(phase14_bytes) != phase14_provenance["artifact_sha256"]:
        raise ValueError("Phase 14 source archive differs from recorded provenance")
    with zipfile.ZipFile(io.BytesIO(phase14_bytes)) as replay:
        if replay.testzip() is not None or len(replay.namelist()) != 2:
            raise ValueError("Phase 14 source archive is damaged or has unexpected members")
        for member in replay.namelist():
            payload = replay.read(member)
            report_name = member.rsplit("/", 1)[-1]
            if report_name not in phase14_provenance["reports"]:
                raise ValueError("unexpected Phase 14 replay member")
            if payload != files[f"experiments/phase14_ci_replay/2026-10-20/auditable/{report_name}"]:
                raise ValueError("Phase 14 report differs from replay archive")
            for pattern in DIRECT_IDENTIFIERS:
                if pattern.search(member.encode()) or pattern.search(payload):
                    raise ValueError("direct identifier in Phase 14 replay member")
            for match in EMAIL.findall(payload):
                if not match.lower().endswith((b"@example.test", b"@example.com")):
                    raise ValueError("email-like value in Phase 14 replay member")
    files["data/replay/phase14-original.zip"] = phase14_bytes
    provider_bytes = PROVIDER_ARCHIVE.read_bytes()
    with zipfile.ZipFile(io.BytesIO(provider_bytes)) as replay:
        if replay.testzip() is not None or "manifest.json" not in replay.namelist():
            raise ValueError("local provider replay is invalid")
        provider_manifest = json.loads(replay.read("manifest.json"))
        for member in replay.namelist():
            payload = replay.read(member)
            if member != "manifest.json" and _sha(payload) != provider_manifest["files"][member]:
                raise ValueError(f"local provider replay member differs: {member}")
            for pattern in DIRECT_IDENTIFIERS:
                if pattern.search(member.encode()) or pattern.search(payload):
                    raise ValueError(f"direct identifier in provider replay: {member}")
            for match in EMAIL.findall(payload):
                if not match.lower().endswith((b"@example.test", b"@example.com")):
                    raise ValueError(f"email-like value in provider replay: {member}")
    files["data/replay/provider-local.zip"] = provider_bytes
    ci_provenance = json.loads((PROVIDER_CI / "private_provenance.json").read_text(encoding="utf-8"))
    for provider, reports in PROVIDER_CI_REPORTS.items():
        record = ci_provenance["artifacts"][provider]
        ci_bytes = (PROVIDER_CI / provider / "github-artifact.zip").read_bytes()
        if _sha(ci_bytes) != record["github_archive_sha256"]:
            raise ValueError(f"provider CI archive differs from GitHub digest: {provider}")
        with zipfile.ZipFile(io.BytesIO(ci_bytes)) as replay:
            if replay.testzip() is not None or set(replay.namelist()) != set(reports):
                raise ValueError(f"invalid provider CI archive: {provider}")
            for report in reports:
                payload = replay.read(report)
                source = PROVIDER_CI / provider / report
                if payload != source.read_bytes() or _sha(payload) != record["reports"][report]:
                    raise ValueError(f"provider CI report differs: {provider}/{report}")
                files[f"data/replay/ci/{report}"] = payload
                for pattern in DIRECT_IDENTIFIERS:
                    if pattern.search(report.encode()) or pattern.search(payload):
                        raise ValueError(f"direct identifier in provider CI report: {report}")
                for match in EMAIL.findall(payload):
                    if not match.lower().endswith((b"@example.test", b"@example.com")):
                        raise ValueError(f"email-like value in provider CI report: {report}")
        files[f"data/replay/{provider}-ci-original.zip"] = ci_bytes
    files["README.md"] = (
        "# Anonymous staged review artifact\n\n"
        "Contains synthetic C1/C2/C3 rows, result tables, selected public "
        "browser and provider reports, protocols, source, and a CXP draft "
        "structure probe, an experimental HPKE/JWE ZIP round trip, and a "
        "separate external JOSE-library cryptographic test and a "
        "project CXP-shaped ZIP using that library. It also contains "
        "a bidirectional direct-HPKE exchange with Proton's open library, "
        "which is not the draft ZIP/JWE profile. "
        "Git history, commit IDs in raw rows, "
        "and original provenance manifests were intentionally omitted. The "
        "original Phase 14 replay ZIP is included and checked byte-for-byte "
        "against its two reports.\n\n"
        "Run python verify.py after extraction. With dependencies installed, "
        "run python tools/verify_provider_reports.py, "
        "python tools/verify_cxp_zip_jwe_reports.py, "
        "python tools/verify_jose_hpke_go_interop.py, "
        "python tools/verify_cxp_jose_zip_go.py, "
        "python tools/verify_proton_cxp_wire_reports.py, "
        "python tools/run_cxp_wire_probe.py and "
        "PYTHONPATH=src python -m pytest tests/test_cxp_wire_probe.py "
        "(set PYTHONPATH appropriately on Windows).\n\n"
        "This package supports internal review of synthetic controls and "
        "public signature reports. The Phase 14 replay ZIP, a local "
        "Fenko/Proton replay bundle, and both original clean-CI provider "
        "ZIPs are included. The provider CI run is same-team execution, "
        "not an independent replication; its identifying run mapping is "
        "held outside this archive. No stable anonymous link exists. This is "
        "not yet a complete submission artifact. "
        "No independent review or external provider CXP transfer is claimed.\n"
    ).encode()
    files["verify.py"] = _source_bytes("tools/verify_anonymous_artifact.py")
    for name, data in files.items():
        for pattern in DIRECT_IDENTIFIERS:
            if pattern.search(data):
                raise ValueError(f"direct identifier in {name}: {pattern.pattern!r}")
        for match in EMAIL.findall(data):
            if not match.lower().endswith((b"@example.test", b"@example.com")):
                raise ValueError(f"email-like value in {name}: {match!r}")
    manifest = {
        "artifact": "passkeytransit-anonymous-staging-v1",
        "scope": "synthetic-campaign-replays-external-type-parsers-experimental-zip-jwe",
        "files": {name: _sha(data) for name, data in sorted(files.items())},
        "source_release_raw_rows": "v0.7.1 synthetic evidence, source_commit field removed",
        "limitations": [
            "local provider replay has no CI provenance; separate same-team clean-CI provider replays are retained",
            "clean CI execution does not establish independent replication or installed provider-app transfer",
            "HPKE/JWE decryption is project-authored experimental; no external provider CXP transfer is evidenced",
            "Proton direct-HPKE library exchange does not implement draft CXP ZIP/JWE or durable provider import",
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
    # Keep the identifying GitHub run reference out of the anonymous ZIP.
    (OUT / "private_provenance.json").write_text(json.dumps({
        "phase14_archive_sha256": _sha(phase14_bytes),
        "github_run_url": phase14_provenance["workflow_run_url"],
        "github_artifact_id": phase14_provenance["artifact_id"],
        "github_digest_confirmed": phase14_provenance["artifact_sha256"],
        "github_metadata_checked_on": "2026-10-21",
        "provider_ci_workflow_run_url": ci_provenance["workflow_run_url"],
        "provider_ci_head_sha": ci_provenance["head_sha"],
        "provider_ci_artifacts": ci_provenance["artifacts"],
        "distribution": "local-private-sidecar-only",
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


if __name__ == "__main__":
    print(build())
