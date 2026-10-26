"""Exercise a cxporter index-layout control inside the pinned PoC envelope.

This transforms a PoC self-export with the decrypted synthetic cxporter index.
It does not turn the original cxporter ZIP into a successful PoC import.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from extract_cxp_public_index import extract
from verify_cxp_public_vector import EXPECTED_ARCHIVE

ROOT = Path(__file__).resolve().parents[1]
TS_COMMIT = "fee19d9ac392ffe0153bea8b917aa0a66f12b272"
EXPECTED_ERROR = "CxpPayloadError: index.jwe is not {header, documents}"


def run(ts_source: Path, vector: Path, index: Path, output: Path) -> dict:
    ts_source, vector, index, output = map(Path.resolve, (ts_source, vector, index, output))
    revision = subprocess.check_output(["git", "-C", str(ts_source), "rev-parse", "HEAD"], text=True).strip()
    if revision != TS_COMMIT:
        raise ValueError("second importer revision differs from pin")
    expected = extract(vector)
    actual = json.loads(index.read_text(encoding="utf-8"))
    if actual != expected or actual["source_archive_sha256"] != EXPECTED_ARCHIVE:
        raise ValueError("decrypted synthetic source index differs")
    adapter = ROOT / "interop/cxp_poc2_cross_probe/pt-index-control.ts"
    shutil.copyfile(adapter, ts_source / "src/cli/pt-index-control.ts")
    pnpm = shutil.which("pnpm")
    if pnpm is None:
        raise FileNotFoundError("pnpm is required for the pinned TypeScript importer")
    process = subprocess.run(
        [pnpm, "exec", "tsx", "src/cli/pt-index-control.ts", str(vector), str(index)],
        cwd=ts_source, capture_output=True, text=True, timeout=90,
    )
    if process.returncode:
        raise RuntimeError(process.stderr.strip())
    observed = json.loads(process.stdout)
    if observed["positive_self_import_items"] != 1 or observed["importer_error"] != EXPECTED_ERROR:
        raise ValueError("index-shape control outcome differs")
    if observed["replacement_index_jwe_alg"] != "dir" or observed["source_archive_sha256"] != EXPECTED_ARCHIVE:
        raise ValueError("index-shape control profile or source differs")
    report = {
        "status": "EXPECTED_REJECTION_AFTER_ADAPTER_TRANSFORMATION",
        "source_commits": {"cxporter": "96bab31fdadcfd295542bba86b8ec8bd2355294a", "cxp_poc2": TS_COMMIT},
        "adapter_sha256": hashlib.sha256(adapter.read_bytes()).hexdigest(),
        "index_sha256": actual["index_sha256"],
        "observation": observed,
        "limitation": "PoC envelope re-encrypts cxporter index plaintext; not original cxporter ciphertext or provider transfer",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ts-source", type=Path, required=True)
    parser.add_argument("--vector", type=Path, default=ROOT / "experiments/cxporter_cxp_open/vectors/cxporter-poc2-v1.json")
    parser.add_argument("--index", type=Path, default=ROOT / "experiments/cxporter_cxp_open/vectors/cxporter-index-v1.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.ts_source, args.vector, args.index, args.output)
    print(json.dumps({"status": report["status"], "importer_error": report["observation"]["importer_error"]},
                     sort_keys=True))


if __name__ == "__main__":
    main()
