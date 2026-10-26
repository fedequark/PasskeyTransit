"""Replay the pinned PoC's own migration through its local WebAuthn RP."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = "fee19d9ac392ffe0153bea8b917aa0a66f12b272"
CASES = (("indirect", "spec-minimal"), ("direct", "spec-minimal"),
         ("indirect", "hardened"), ("direct", "hardened"))


def run(source: Path, output: Path) -> dict:
    source = source.resolve()
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if revision != PIN:
        raise ValueError("PoC source revision differs from pin")
    probe = ROOT / "interop/cxp_poc2_cross_probe/pt-rp-control.ts"
    shutil.copyfile(probe, source / "src/cli/pt-rp-control.ts")
    pnpm = shutil.which("pnpm")
    if pnpm is None:
        raise FileNotFoundError("pnpm is required")
    cases = []
    for mode, profile in CASES:
        process = subprocess.run(
            [pnpm, "exec", "tsx", "src/cli/pt-rp-control.ts", mode, profile],
            cwd=source, capture_output=True, text=True, timeout=90,
        )
        if process.returncode:
            raise RuntimeError(f"{mode}/{profile}: {process.stderr.strip()}")
        observed = json.loads(process.stdout)
        if observed["mode"] != mode or observed["profile"] != profile:
            raise ValueError("case identity differs")
        cases.append(observed)
    report = {
        "status": "SAME_CODEBASE_RP_CONTROL_PASS",
        "source_commit": PIN,
        "probe_sha256": hashlib.sha256(probe.read_bytes()).hexdigest(),
        "cases": cases,
        "limitation": "PoC Provider A and B share one codebase; does not import cxporter ciphertext or represent installed provider apps",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ts-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.ts_source, args.output)
    print(json.dumps({"status": report["status"], "cases": len(report["cases"])}, sort_keys=True))


if __name__ == "__main__":
    main()
