from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .analysis import run_analysis
from .campaign import run_c1_reference_control
from .browser_campaign import run_browser_c1
from .cxp import run_cxp_reference
from .experiment import run_pilot
from .protocol import validate_protocol
from .requirements import requirement_coverage
from .robustness import run_c2_robustness, run_c3_faults
from .interop import run_independent_interop
from .external_adapter import run_bitwarden_interop
from .oracle_capabilities import write_oracle_capability_report
from .release import build_release, verify_release
from .webauthn_lab import run_webauthn_migration


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
    webauthn = subparsers.add_parser("webauthn", help="run a real browser WebAuthn migration")
    webauthn.add_argument("--browser", type=Path, required=True)
    webauthn.add_argument("--output", type=Path, required=True)
    cxp = subparsers.add_parser("cxp", help="run the experimental CXP/HPKE reference exchange")
    cxp.add_argument("--output", type=Path, required=True)
    campaign = subparsers.add_parser("campaign-c1", help="run the Phase 5 C1 reference-control campaign")
    campaign.add_argument("--protocol", type=Path, required=True)
    campaign.add_argument("--output", type=Path, required=True)
    c2 = subparsers.add_parser("campaign-c2", help="run the Phase 6 C2 robustness controls")
    c2.add_argument("--protocol", type=Path, required=True)
    c2.add_argument("--output", type=Path, required=True)
    c3 = subparsers.add_parser("campaign-c3", help="run the Phase 6 C3 fault controls")
    c3.add_argument("--protocol", type=Path, required=True)
    c3.add_argument("--output", type=Path, required=True)
    browser_c1 = subparsers.add_parser("browser-c1", help="run the Phase 7 browser-backed C1 campaign")
    browser_c1.add_argument("--protocol", type=Path, required=True)
    browser_c1.add_argument("--browser", type=Path, required=True)
    browser_c1.add_argument("--output", type=Path, required=True)
    browser_c1.add_argument("--mode", choices=("calibration", "full"), required=True)
    interop = subparsers.add_parser("interop", help="run Phase 8 independent interoperability checks")
    interop.add_argument("--node", type=Path, required=True)
    interop.add_argument("--node-verifier", type=Path, required=True)
    interop.add_argument("--output", type=Path, required=True)
    analysis = subparsers.add_parser("analyze", help="generate the Phase 9 analysis and manuscript")
    analysis.add_argument("--phase7-summary", type=Path, required=True)
    analysis.add_argument("--phase7-manifest", type=Path, required=True)
    analysis.add_argument("--c2-summary", type=Path, required=True)
    analysis.add_argument("--c2-manifest", type=Path, required=True)
    analysis.add_argument("--c3-summary", type=Path, required=True)
    analysis.add_argument("--c3-manifest", type=Path, required=True)
    analysis.add_argument("--interop", type=Path, required=True)
    analysis.add_argument("--output", type=Path, required=True)
    analysis.add_argument("--external", type=Path)
    analysis.add_argument("--oracle-report", type=Path)
    external = subparsers.add_parser("bitwarden-interop", help="run the pinned Bitwarden CXF adapter")
    external.add_argument("--protocol", type=Path, required=True)
    external.add_argument("--cargo", type=Path, required=True)
    external.add_argument("--manifest", type=Path, required=True)
    external.add_argument("--node", type=Path, required=True)
    external.add_argument("--wasi-runner", type=Path, required=True)
    external.add_argument("--cargo-toolchain")
    external.add_argument("--output", type=Path, required=True)
    oracle_audit = subparsers.add_parser("oracle-audit", help="write the Phase 12 capability report")
    oracle_audit.add_argument("--output", type=Path, required=True)
    release = subparsers.add_parser("release", help="build a self-contained replication archive")
    release.add_argument("--project-root", type=Path, required=True)
    release.add_argument("--evidence-root", type=Path, action="append", required=True)
    release.add_argument("--external-result", type=Path, required=True)
    release.add_argument("--oracle-report", type=Path, required=True)
    release.add_argument("--output", type=Path, required=True)
    release_verify = subparsers.add_parser("verify-release", help="verify a replication archive")
    release_verify.add_argument("--archive", type=Path, required=True)
    release_verify.add_argument("--manifest", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "status":
        print(
            json.dumps(
                {
                    "version": __version__,
                    "phase": "13-publication-package",
                    "evidence_class": "reference-control-research-package",
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
    if args.command == "webauthn":
        result = run_webauthn_migration(args.browser, args.output)
        print(json.dumps(result, indent=2))
        return 0 if result["all_checks_pass"] else 1
    if args.command == "cxp":
        result = run_cxp_reference(args.output)
        print(json.dumps(result, indent=2))
        return 0 if result["round_trip_equal"] else 1
    if args.command == "campaign-c1":
        result = run_c1_reference_control(args.protocol, args.output)
        print(json.dumps(result, indent=2))
        return 0 if result["summary"]["repeat_equivalent"] else 1
    if args.command == "campaign-c2":
        result = run_c2_robustness(args.protocol, args.output)
        print(json.dumps(result, indent=2))
        return 0
    if args.command == "campaign-c3":
        result = run_c3_faults(args.protocol, args.output)
        print(json.dumps(result, indent=2))
        return 0 if result["summary"]["failure_sequence_count"] == 960 else 1
    if args.command == "browser-c1":
        result = run_browser_c1(
            args.protocol, args.browser, args.output, calibration=args.mode == "calibration"
        )
        print(json.dumps(result, indent=2))
        return 0 if result["summary"]["oracle_statuses"]["webauthn_assertion"] == {"PASS": result["summary"]["attempt_count"]} else 1
    if args.command == "interop":
        result = run_independent_interop(args.node, args.node_verifier, args.output)
        print(json.dumps(result, indent=2))
        return 0 if result["all_applicable_checks_pass"] else 1
    if args.command == "analyze":
        result = run_analysis(
            args.phase7_summary, args.phase7_manifest, args.c2_summary, args.c2_manifest,
            args.c3_summary, args.c3_manifest, args.interop, args.output,
            args.external, args.oracle_report,
        )
        print(json.dumps({"output": str(args.output), "claim_boundary_enforced": result["manifest"]["claim_boundary_enforced"]}, indent=2))
        return 0
    if args.command == "bitwarden-interop":
        result = run_bitwarden_interop(
            args.protocol, args.cargo, args.manifest, args.node, args.wasi_runner, args.output,
            args.cargo_toolchain,
        )
        print(json.dumps(result, indent=2))
        return 0 if result["semantic_json_equal"] else 1
    if args.command == "oracle-audit":
        print(json.dumps(write_oracle_capability_report(args.output), indent=2))
        return 0
    if args.command == "release":
        result = build_release(
            args.project_root, args.evidence_root, args.external_result, args.oracle_report, args.output
        )
        print(json.dumps(result, indent=2))
        return 0
    if args.command == "verify-release":
        result = verify_release(args.archive, args.manifest)
        print(json.dumps(result, indent=2))
        return 0 if result["verified"] else 1
    result = run_pilot(args.config, args.output)
    print(json.dumps(result, indent=2))
    return 0
