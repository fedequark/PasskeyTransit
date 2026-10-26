"""Package local synthetic Fenko and Proton replays with exact source snapshots.

The bundle is a local-run evidence package, not an externally attested CI run.
"""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiments/provider_replays/2026-10-26"
FENKO = ROOT / "tmp/vendor_fenko"
PROTON_WASM = ROOT / "interop/proton-cxf-prf/node_modules/@protontech/pass-rust-core/worker/proton_pass_web_bg.wasm"
REPORTS = {
    "fenko_provider.json": "datasets/generated/phase15/20261026-replay/fenko_provider.json",
    "fenko_roundtrip.json": "datasets/generated/phase16/20261026-replay/fenko_roundtrip.json",
    "proton_cxf_prf.json": "datasets/generated/phase17/20261026-replay/proton_cxf_prf.json",
}
PROJECT_FILES = [
    "LICENSE", "pyproject.toml", "requirements.lock",
    "experiments/protocol_v2.json",
    "experiments/protocol_v2_fenko_roundtrip.json",
    "experiments/protocol_v2_proton_software.json",
    "interop/proton-cxf-prf/package.json",
    "interop/proton-cxf-prf/package-lock.json",
    "interop/proton-cxf-prf/run.mjs",
    "tools/run_proton_cxf_prf.py",
    "tools/verify_proton_public_report.py",
    "tools/verify_provider_replay_bundle.py",
]
FENKO_FILES = [
    "LICENSE", "package-lock.json", "src/porting/formats/cxf.ts",
    "src/porting/import.ts", "src/porting/export.ts", "src/background/prf.ts",
]
DIRECT_IDENTIFIERS = [
    re.compile(rb"(?i)github\.com/fedequark(?:/|\b)"),
    re.compile(rb"(?i)(?<![A-Za-z0-9])fedep(?![A-Za-z0-9])"),
    re.compile(rb"(?i)C:[/\\]Users[/\\]"),
]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build() -> Path:
    files = {f"reports/{name}": (ROOT / source).read_bytes() for name, source in REPORTS.items()}
    files.update({name: (ROOT / name).read_bytes() for name in PROJECT_FILES})
    files.update({
        source.relative_to(ROOT).as_posix(): source.read_bytes()
        for source in sorted((ROOT / "src/passkeytransit").glob("*.py"))
    })
    files.update({f"vendor/fenko/{name}": (FENKO / name).read_bytes() for name in FENKO_FILES})
    fenko = json.loads(files["reports/fenko_provider.json"])
    roundtrip = json.loads(files["reports/fenko_roundtrip.json"])
    proton = json.loads(files["reports/proton_cxf_prf.json"])
    if fenko["runner_sha256"] != digest(files["src/passkeytransit/fenko_provider.py"]):
        raise ValueError("Fenko runner does not match report")
    if roundtrip["runner_sha256"] != digest(files["src/passkeytransit/fenko_roundtrip.py"]):
        raise ValueError("Fenko roundtrip runner does not match report")
    for report, protocol in (
        (fenko, "experiments/protocol_v2.json"),
        (roundtrip, "experiments/protocol_v2_fenko_roundtrip.json"),
    ):
        if report["protocol_sha256"] != digest(files[protocol]):
            raise ValueError("Fenko protocol does not match report")
        for name, expected in report["provider"]["source_file_sha256"].items():
            if digest(files[f"vendor/fenko/{name}"]) != expected:
                raise ValueError(f"Fenko source does not match report: {name}")
    expected_proton = proton["artifact_sha256"]
    for name, path in {
        "npm_lockfile": "interop/proton-cxf-prf/package-lock.json",
        "node_adapter": "interop/proton-cxf-prf/run.mjs",
        "python_driver": "tools/run_proton_cxf_prf.py",
    }.items():
        if digest(files[path]) != expected_proton[name]:
            raise ValueError(f"Proton {name} does not match report")
    if digest(PROTON_WASM.read_bytes()) != expected_proton["proton_worker_wasm"]:
        raise ValueError("installed Proton worker differs from report")
    for name, data in files.items():
        for pattern in DIRECT_IDENTIFIERS:
            if pattern.search(data):
                raise ValueError(f"direct author identifier in {name}")
    files["README.md"] = (
        "# Local provider replay, 2026-10-26\n\n"
        "Synthetic Fenko browser and Proton WASM reports, exact project runner "
        "snapshots, selected pinned Fenko source, and dependency locks. Run "
        "python verify.py after extraction with the project Python dependencies. "
        "The verifier checks hashes, 40 Fenko signatures, 18 Fenko PRF witness "
        "links, 12 Proton signatures and 12 Proton PRF digest relationships. "
        "It does not independently attest local execution or provider private state.\n\n"
        "Fenko source commit: 2d873fbe25257250de6e322e9d785b97b17a544f. "
        "Proton source commit: 69a0927f0fe7071243d6c38e404459a69210fdd4. "
        "The Proton worker WASM is omitted; npm ci with the pinned lockfile "
        "restores it for an executable rerun. Browser profiles, vaults, keys, "
        "HMAC seeds, raw PRF outputs, and plaintext CXF are not retained.\n"
    ).encode()
    files["verify.py"] = files["tools/verify_provider_replay_bundle.py"]
    manifest = {
        "schema_version": 1,
        "evidence_scope": "same-host local replays; no CI attestation or independent provider wire CXP",
        "fenko_browser_version": fenko["browser_version"],
        "fenko_source_commit": fenko["provider"]["source_revision"],
        "proton_source_commit": proton["proton_source_commit"],
        "proton_worker_wasm_sha256": expected_proton["proton_worker_wasm"],
        "files": {name: digest(data) for name, data in sorted(files.items())},
    }
    files["manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / "provider-replay-local.zip"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    (OUT / "audit.json").write_text(json.dumps({
        "archive_sha256": digest(target.read_bytes()),
        "file_count": len(files),
        "scope": manifest["evidence_scope"],
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


if __name__ == "__main__":
    print(build())
