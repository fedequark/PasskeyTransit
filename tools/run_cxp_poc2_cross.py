"""Run an unchanged second open importer against pinned cxporter ZIP/JWE output.

The adapter is copied inside the second module to import its public source
files. Both implementations' source commits are checked before execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from passkeytransit.cxf import build_passkey_document
from passkeytransit.model import generate_synthetic_passkey

ROOT = Path(__file__).resolve().parents[1]
GO_COMMIT = "96bab31fdadcfd295542bba86b8ec8bd2355294a"
TS_COMMIT = "fee19d9ac392ffe0153bea8b917aa0a66f12b272"
EXPECTED_ERROR = 'JweError: JWE decryption failed: "alg" (Algorithm) Header Parameter value not allowed'
EXPECTED_SCHEMA_ERROR = "CxpValidationError: Malformed ExportResponse: $.archive: Invalid input: expected string, received undefined"


def revision(path: Path) -> str:
    return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()


def run(binary: Path, go_source: Path, ts_source: Path, output: Path) -> dict:
    if revision(go_source) != GO_COMMIT or revision(ts_source) != TS_COMMIT:
        raise ValueError("external source revision differs from pin")
    adapter = ROOT / "interop/cxp_poc2_cross_probe/pt-cross.ts"
    target = ts_source / "src/cli/pt-cross.ts"
    shutil.copyfile(adapter, target)
    pnpm = shutil.which("pnpm")
    if pnpm is None:
        raise FileNotFoundError("pnpm is required for the pinned TypeScript importer")
    runs = []
    for repetition in range(2):
        document = build_passkey_document(
            generate_synthetic_passkey(20261026, repetition + 1),
            timestamp=1_700_000_000,
            hmac_with_uv=hashlib.sha256(f"cxporter:{repetition}:uv".encode()).digest(),
            hmac_without_uv=hashlib.sha256(f"cxporter:{repetition}:no-uv".encode()).digest(),
        )
        process = subprocess.run(
            [pnpm, "exec", "tsx", "src/cli/pt-cross.ts", str(binary)],
            cwd=ts_source, input=json.dumps(document), text=True, capture_output=True,
            timeout=60, check=True,
        )
        observed = json.loads(process.stdout)
        if observed["second_source_commit"] != TS_COMMIT or observed["self_import_items"] != 1:
            raise ValueError("second importer provenance or positive control failed")
        if observed["self_import_passkey_state_preserved"] is not True:
            raise ValueError("second importer's self-test changed passkey state")
        if observed["cross_import_rejected"] is not True or observed["cross_import_error"] != EXPECTED_ERROR:
            raise ValueError("cross-import rejection differs from expected algorithm mismatch")
        if observed["response_archive_field_present"] is not False:
            raise ValueError("response schema result differs from cxporter control")
        if observed["response_schema_rejected"] is not True or observed["response_schema_error"] != EXPECTED_SCHEMA_ERROR:
            raise ValueError("second parser did not reject the missing archive field")
        if observed["cxporter_jwe_alg"] != "HPKE-Base-X25519-SHA256-AES256GCM":
            raise ValueError("cxporter JWE algorithm changed")
        runs.append({"repetition": repetition, **observed})
    report = {
        "source_commits": {"cxporter": GO_COMMIT, "cxp_poc2": TS_COMMIT},
        "adapter_sha256": hashlib.sha256(adapter.read_bytes()).hexdigest(),
        "classification": "two open implementations; cxporter exporter to cxp_poc2 experimental importer",
        "interoperability": "FAIL_RESPONSE_SCHEMA_AND_JWE_ALGORITHM",
        "status": "EXPECTED_REJECTION",
        "runs": runs,
        "limitations": [
            "cxp_poc2 is a research PoC, not an installed credential provider",
            "this rejects before CXF reconstruction; it does not test persistent vault import or RP use",
            "different CXP draft gap choices, not proof of nonconformance by either implementation",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--go-source", type=Path, required=True)
    parser.add_argument("--ts-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.binary.resolve(), args.go_source.resolve(),
                 args.ts_source.resolve(), args.output.resolve())
    print(json.dumps({"status": report["status"], "interoperability": report["interoperability"],
                      "runs": len(report["runs"])}, sort_keys=True))


if __name__ == "__main__":
    main()
