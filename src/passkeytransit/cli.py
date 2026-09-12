from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .experiment import run_pilot
from .protocol import validate_protocol
from .requirements import requirement_coverage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="passkeytransit")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status", help="show baseline capability status")
    pilot = subparsers.add_parser("pilot", help="run the deterministic pilot")
    pilot.add_argument("--config", type=Path, required=True)
    pilot.add_argument("--output", type=Path, required=True)
    protocol = subparsers.add_parser("protocol", help="validate the frozen protocol")
    protocol.add_argument("--config", type=Path, required=True)
    requirements = subparsers.add_parser("requirements", help="audit CXF requirement coverage")
    requirements.add_argument("--matrix", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "status":
        print(
            json.dumps(
                {
                    "version": __version__,
                    "phase": "2-cxf-passkey-profile",
                    "evidence_class": "synthetic-policy-control",
                },
                indent=2,
            )
        )
        return 0
    if args.command == "protocol":
        print(json.dumps(validate_protocol(args.config), indent=2))
        return 0
    if args.command == "requirements":
        print(json.dumps(requirement_coverage(args.matrix), indent=2))
        return 0
    result = run_pilot(args.config, args.output)
    print(json.dumps(result, indent=2))
    return 0
