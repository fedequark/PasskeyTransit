"""Replay cxporter ciphertext through an explicit project adapter to PoC RP."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GO_PIN = "96bab31fdadcfd295542bba86b8ec8bd2355294a"
TS_PIN = "fee19d9ac392ffe0153bea8b917aa0a66f12b272"


def run(binary: Path, go_source: Path, ts_source: Path, output: Path) -> dict:
    binary, go_source, ts_source = binary.resolve(), go_source.resolve(), ts_source.resolve()
    for source, pin in ((go_source, GO_PIN), (ts_source, TS_PIN)):
        revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        if revision != pin:
            raise ValueError("source revision differs from pin")
    probe = ROOT / "interop/cxp_poc2_cross_probe/pt-adapter-rp.ts"
    helper = ROOT / "tools/cxporter_to_poc2_rp_adapter.py"
    shutil.copyfile(probe, ts_source / "src/cli/pt-adapter-rp.ts")
    pnpm = shutil.which("pnpm")
    if pnpm is None:
        raise FileNotFoundError("pnpm is required")
    observations = []
    for _ in range(2):
        process = subprocess.run(
            [pnpm, "exec", "tsx", "src/cli/pt-adapter-rp.ts", sys.executable, str(helper), str(binary)],
            cwd=ts_source, capture_output=True, text=True, timeout=90,
        )
        if process.returncode:
            raise RuntimeError(process.stderr.strip())
        observed = json.loads(process.stdout)
        if observed["status"] != "ADAPTER_RP_CONTROL_PASS":
            raise ValueError("adapter RP control failed")
        observations.append(observed)
    if observations[0]["archive_sha256"] == observations[1]["archive_sha256"]:
        raise ValueError("fresh exports should differ")
    report = {
        "status": "PROJECT_ADAPTER_RP_CONTROL_PASS",
        "source_commits": {"cxporter": GO_PIN, "cxp_poc2": TS_PIN},
        "probe_sha256": hashlib.sha256(probe.read_bytes()).hexdigest(),
        "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        "runs": observations,
        "limitation": "project Python decryptor and direct PoC vault insertion bypass PoC CXP importer; not independent provider wire interoperability",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes((json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--go-source", type=Path, required=True)
    parser.add_argument("--ts-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.binary, args.go_source, args.ts_source, args.output)
    print(json.dumps({"status": report["status"], "runs": len(report["runs"])}, sort_keys=True))


if __name__ == "__main__":
    main()
