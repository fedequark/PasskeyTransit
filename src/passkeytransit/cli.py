from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .experiment import run_pilot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="passkeytransit")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status", help="show baseline capability status")
    pilot = subparsers.add_parser("pilot", help="run the deterministic pilot")
    pilot.add_argument("--config", type=Path, required=True)
    pilot.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "status":
        print(
            json.dumps(
                {
                    "version": __version__,
                    "phase": "0-baseline-reconstructed",
                    "evidence_class": "synthetic-policy-control",
                },
                indent=2,
            )
        )
        return 0
    result = run_pilot(args.config, args.output)
    print(json.dumps(result, indent=2))
    return 0

