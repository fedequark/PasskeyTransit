"""Scope an independent CXF format check to one public synthetic fixture."""

import argparse
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "experiments/cxporter_cxp_open/vectors/cxporter-poc2-v1.json"
PIN = "94d49c95c12ba28e1058e290010c0826820fcea5"


def run(kit: Path, arguments: list[str]) -> tuple[int, dict]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(kit / "src")
    result = subprocess.run(
        [sys.executable, "-m", "cxf_kit", *arguments, "--format", "json"],
        cwd=kit,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if not result.stdout.strip():
        raise RuntimeError(f"cxf-kit produced no JSON: {result.stderr.strip()}")
    return result.returncode, json.loads(result.stdout)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    kit = args.kit.resolve()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=kit, text=True).strip()
    if commit != PIN:
        raise RuntimeError(f"Unexpected cxf-kit commit: {commit}")
    vector = json.loads(VECTOR.read_text(encoding="utf-8"))
    source = vector["cxf"]
    credential = source["accounts"][0]["items"][0]["credentials"][0]
    if credential["type"] != "passkey" or source["accounts"][0]["items"][0]["title"] != "Synthetic User 91":
        raise RuntimeError("Unexpected synthetic fixture")

    with tempfile.TemporaryDirectory() as tmp:
        baseline = Path(tmp) / "baseline.json"
        invalid = Path(tmp) / "invalid.json"
        changed = Path(tmp) / "changed.json"
        baseline.write_text(json.dumps(source), encoding="utf-8")
        malformed = copy.deepcopy(source)
        del malformed["version"]
        invalid.write_text(json.dumps(malformed), encoding="utf-8")
        altered = copy.deepcopy(source)
        key = altered["accounts"][0]["items"][0]["credentials"][0]["key"]
        altered["accounts"][0]["items"][0]["credentials"][0]["key"] = ("A" if key[0] != "A" else "B") + key[1:]
        changed.write_text(json.dumps(altered), encoding="utf-8")

        valid_code, valid = run(kit, ["validate", str(baseline)])
        invalid_code, invalid_result = run(kit, ["validate", str(invalid)])
        change_code, change = run(kit, ["compare", "--before", str(baseline), "--after", str(changed)])
        roundtrip_code, roundtrip = run(kit, ["roundtrip", "--input", str(baseline)])

    if valid_code != 0 or not valid["valid"] or valid["credential_types"] != ["passkey"]:
        raise RuntimeError("The independent validator rejected the baseline")
    if invalid_code == 0 or invalid_result["valid"] or not any(f["severity"] == "error" for f in invalid_result["findings"]):
        raise RuntimeError("The independent validator accepted the missing-version control")
    if change_code == 0 or change["classification"] != "semantic_loss" or change["summary"]["changed_values"] < 1:
        raise RuntimeError("The independent comparator missed the changed-key control")
    if roundtrip_code != 0 or roundtrip["classification"] != "passed" or roundtrip["summary"]["lost_values"] != 0:
        raise RuntimeError("The independent canonical roundtrip failed")

    report = {
        "scope": "Independent structural CXF validation of a project-authored synthetic fixture; no CXP transfer, vault import, RP assertion, or cryptographic key validation",
        "kit": "pengshuhao62-lang/credential-exchange-conformance-kit",
        "kit_commit": commit,
        "profile": valid["profile"],
        "cxf_canonical_sha256": hashlib.sha256(json.dumps(source, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest(),
        "baseline": {"valid": valid["valid"], "credential_types": valid["credential_types"], "credential_count": valid["credential_count"], "findings": [f["code"] for f in valid["findings"]]},
        "missing_version_control": {"rejected": invalid_code != 0 and not invalid_result["valid"], "findings": [f["code"] for f in invalid_result["findings"]]},
        "changed_key_control": {"classification": change["classification"], "changed_values": change["summary"]["changed_values"], "findings": [f["code"] for f in change["findings"]]},
        "canonical_roundtrip": {"classification": roundtrip["classification"], "comparable_values": roundtrip["summary"]["comparable_values"], "preserved_values": roundtrip["summary"]["preserved_values"]},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
