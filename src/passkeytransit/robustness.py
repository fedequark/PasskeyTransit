from __future__ import annotations

import copy
import hashlib
import json
import platform
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .campaign import (
    ORACLES,
    _apply_profile,
    _canonical,
    _classify,
    _evaluate,
    _evidence,
    _oracle,
    _passkey,
    _transport,
    build_c1_corpus,
)
from .cxf import validate_passkey_document
from .model import b64url, generate_synthetic_passkey, unb64url
from .protocol import validate_protocol


MUTATION_REQUIREMENTS = {
    "missing-required": "CXF-HDR-001",
    "invalid-base64url": "CXF-ENC-002",
    "malformed-pkcs8": "CXF-PK-006",
    "key-mismatch": "CXF-PK-007",
    "rp-id-change": "CXF-PK-004",
    "credential-id-collision": None,
    "unknown-optional-member": "CXF-FWD-001",
    "unknown-required-enum": "CXF-PK-001",
    "minor-version-increase": "CXF-FWD-001",
    "major-version-mismatch": "CXF-VER-001",
}

REQUIREMENT_ORACLES = {
    "CXF-PK-004": "rp_id",
    "CXF-PK-007": "public_key",
}


def _normative_class(
    requirement: dict[str, Any] | None,
    execution: str,
    oracles: dict[str, dict[str, Any]],
    *,
    collision: bool,
) -> str:
    """Classify from requirement metadata and observations, not mutation labels."""
    if requirement is None:
        return "AMBIGUOUS" if collision else "NOT_ASSESSED"
    level = str(requirement.get("level", ""))
    if execution == "REJECTED":
        return "CONFORMANT" if level in {"MUST", "MUST NOT"} else "AMBIGUOUS"
    target = REQUIREMENT_ORACLES.get(str(requirement.get("id")))
    if target and oracles[target]["status"] == "FAIL":
        return "VIOLATION" if level in {"MUST", "MUST NOT"} else "AMBIGUOUS"
    return "CONFORMANT"


def _git_state(project_root: Path) -> tuple[str | None, bool | None]:
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=project_root, text=True).strip()
        unstaged = subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=project_root).returncode
        staged = subprocess.run(["git", "diff", "--cached", "--quiet", "HEAD", "--"], cwd=project_root).returncode
        dirty = unstaged != 0 or staged != 0
        return commit, dirty
    except Exception:
        return None, None


def _paths(output_dir: Path, prefix: str, names: list[str]) -> dict[str, Path]:
    paths = {name: output_dir / f"{prefix}_{name}.jsonl" for name in names}
    paths["summary"] = output_dir / f"{prefix}_summary.json"
    paths["manifest"] = output_dir / f"{prefix}_manifest.json"
    existing = [path for path in paths.values() if path.exists()]
    if existing:
        raise FileExistsError(f"campaign output is immutable; choose a new directory: {existing[0]}")
    return paths


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("x", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _rejected_oracles(findings: list[Any]) -> dict[str, dict[str, Any]]:
    results = {name: _oracle("NOT_APPLICABLE", "import rejected before semantic state") for name in ORACLES}
    results["cxf_structure"] = _oracle(
        "FAIL",
        [finding.__dict__ for finding in findings] if findings else "credential-id collision rejected by control store",
        sorted({finding.requirement_id for finding in findings}) if findings else None,
    )
    return results


def _mutate(document: dict[str, Any], family: str, seed_index: int) -> dict[str, Any]:
    mutated = copy.deepcopy(document)
    passkey = _passkey(mutated)
    if family == "missing-required":
        del mutated["exporterDisplayName"]
    elif family == "invalid-base64url":
        passkey["credentialId"] = "+/invalid"
    elif family == "malformed-pkcs8":
        passkey["key"] = b64url(b"not-a-pkcs8-key")
    elif family == "key-mismatch":
        other = generate_synthetic_passkey(20260912, 10_000 + seed_index)
        passkey["key"] = b64url(other.private_key_pkcs8)
    elif family == "rp-id-change":
        passkey["rpId"] = "changed-rp.example.test"
    elif family == "credential-id-collision":
        passkey_copy = copy.deepcopy(passkey)
        mutated["accounts"][0]["items"][0]["credentials"].append(passkey_copy)
    elif family == "unknown-optional-member":
        passkey["futureOptionalMember"] = {"opaque": "preserve-or-ignore"}
    elif family == "unknown-required-enum":
        passkey["type"] = "future-required-passkey"
    elif family == "minor-version-increase":
        mutated["version"]["minor"] = 1
    elif family == "major-version-mismatch":
        mutated["version"]["major"] = 2
    else:
        raise ValueError(f"unknown mutation family: {family}")
    return mutated


def _has_credential_collision(document: dict[str, Any]) -> bool:
    identifiers: list[str] = []
    for account in document.get("accounts", []):
        for item in account.get("items", []):
            identifiers.extend(
                str(credential.get("credentialId"))
                for credential in item.get("credentials", [])
                if isinstance(credential, dict) and credential.get("type") == "passkey"
            )
    return len(identifiers) != len(set(identifiers))


def _c2_record(
    protocol: dict[str, Any], source: dict[str, Any], mutated: dict[str, Any], stratum: str, index: int,
    family: str, requirements: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    findings = validate_passkey_document(mutated)
    errors = [finding for finding in findings if finding.severity == "error"]
    collision = _has_credential_collision(mutated)
    requirement_id = MUTATION_REQUIREMENTS[family]
    requirement = requirements.get(requirement_id) if requirement_id else None
    if errors or collision:
        oracles = _rejected_oracles(errors)
        if collision and not errors:
            oracles["cxf_structure"] = _oracle("PASS", "valid CXF rejected by duplicate-credential store policy")
        execution = "REJECTED"
        semantic = "NOT_APPLICABLE"
    else:
        properties = set(map(str, protocol["feature_strata"][int(stratum[1:])]["properties"]))
        migrated = _transport(mutated, "reference", "strict")
        try:
            migrated, _ = _apply_profile(
                migrated, "strict", source_document=source, required_properties=properties
            )
        except ValueError:
            oracles = _rejected_oracles([])
            execution = "REJECTED"
            semantic = "NOT_APPLICABLE"
        else:
            oracles = _evaluate(source, migrated, properties)
            execution = "IMPORTED"
            semantic = _classify(oracles, set())
        target = REQUIREMENT_ORACLES.get(requirement_id or "")
        if target and requirement_id:
            oracles[target]["requirement_ids"] = [requirement_id]
    normative = _normative_class(requirement, execution, oracles, collision=collision)
    credential_hash = hashlib.sha256(unb64url(_passkey(source)["credentialId"])).hexdigest()
    return {
        "protocol_id": protocol["protocol_id"],
        "campaign_id": "C2",
        "run_id": "phase6-c2-reference-control-v1",
        "attempt_id": f"C2-{stratum}-{family}",
        "credential_id_hash": credential_hash,
        "feature_stratum": stratum,
        "route_id": "C2-reference-to-strict",
        "seed": protocol["seed"],
        "provider_chain": ["reference", "strict"],
        "hop_count": 1,
        "mutation_id": family,
        "mutation_recipe": {"seed": protocol["seed"], "credential_index": index, "family": family},
        "failure_point": None,
        "retry_index": 0,
        "execution_status": execution,
        "oracles": oracles,
        "semantic_class": semantic,
        "normative_class": normative,
        "normative_evidence": {
            "requirement_id": requirement_id,
            "requirement_level": requirement.get("level") if requirement else None,
            "requirement_actor": requirement.get("actor") if requirement else None,
        },
        "basic_auth_pass": None,
        "false_reassurance": None,
        "exclusion_reason": None,
        "minimal_reproducer_ref": _evidence({"stratum": stratum, "family": family, "document": mutated}),
    }


def run_c2_robustness(protocol_path: Path, output_dir: Path) -> dict[str, Any]:
    paths = _paths(output_dir, "c2_phase6", ["attempts"])
    validate_protocol(protocol_path)
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    requirements_path = protocol_path.resolve().parent.parent / "spec" / "cxf_passkey_requirements_v1.0.json"
    requirements_document = json.loads(requirements_path.read_text(encoding="utf-8"))
    requirements = {item["id"]: item for item in requirements_document["requirements"]}
    corpus = build_c1_corpus(protocol)
    representatives = [next(item for item in corpus if item[1] == f"F{index}") for index in range(8)]
    families = list(map(str, protocol["campaigns"]["C2"]["mutation_families"]))
    rows = [
        _c2_record(protocol, source, _mutate(source, family, index), stratum, index, family, requirements)
        for index, stratum, source in representatives
        for family in families
    ]
    project_root = protocol_path.resolve().parent.parent
    commit, dirty = _git_state(project_root)
    for row in rows:
        row["source_commit"] = commit
        row["environment_id"] = "phase6-robustness-control-v1"
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(paths["attempts"], rows)
    by_family = {
        family: {
            "attempts": sum(row["mutation_id"] == family for row in rows),
            "execution_statuses": dict(Counter(row["execution_status"] for row in rows if row["mutation_id"] == family)),
            "semantic_classes": dict(Counter(row["semantic_class"] for row in rows if row["mutation_id"] == family)),
            "normative_classes": dict(Counter(row["normative_class"] for row in rows if row["mutation_id"] == family)),
        }
        for family in families
    }
    summary = {
        "protocol_id": protocol["protocol_id"],
        "campaign_id": "C2",
        "evidence_class": "synthetic-reference-robustness-control",
        "attempt_count": len(rows),
        "strata": 8,
        "mutation_families": by_family,
        "pooled_preservation_estimate": None,
        "confirmatory_provider_claims_authorized": False,
    }
    with paths["summary"].open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(summary, indent=2) + "\n")
    manifest = _manifest(protocol_path, paths, commit, dirty, ["synthetic mutations and control importer", "C2 families are reported separately and not pooled"])
    with paths["manifest"].open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(manifest, indent=2) + "\n")
    return {"summary": summary, "manifest": manifest}


class _InjectedFailure(RuntimeError):
    pass


def _snapshot(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "copy_count": len(entries),
        "committed_count": sum(bool(entry["committed"]) for entry in entries),
        "state_ref": _evidence(
            [{"committed": entry["committed"], "document_ref": _evidence(entry["document"])} for entry in entries]
        ),
    }


def _transaction(
    source: dict[str, Any], destination: str, failure_point: str | None, entries: list[dict[str, Any]]
) -> tuple[str, set[str]]:
    validate_errors = [finding for finding in validate_passkey_document(source) if finding.severity == "error"]
    if validate_errors:
        return "REJECTED", set()
    if failure_point == "after-validation":
        raise _InjectedFailure
    if failure_point == "after-approval":
        raise _InjectedFailure
    decoded = _transport(source, "reference", destination)
    if failure_point == "after-payload-decode":
        raise _InjectedFailure
    migrated, declarations = _apply_profile(decoded, destination)
    provisional = {"document": migrated, "committed": False}
    entries.append(provisional)
    if failure_point in {"after-provisional-persistence", "before-commit"}:
        if destination != "legacy":
            entries.remove(provisional)
        raise _InjectedFailure
    provisional["committed"] = True
    return "IMPORTED", declarations


def _c3_sequence(
    protocol: dict[str, Any], index: int, stratum: str, source: dict[str, Any], destination: str, failure_point: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    entries: list[dict[str, Any]] = []
    before = _snapshot(entries)
    try:
        _transaction(source, destination, failure_point, entries)
        initial_status = "ERROR"
    except _InjectedFailure:
        initial_status = "PARTIAL" if entries else "ROLLED_BACK"
    after_failure = _snapshot(entries)
    retry_status, declarations = _transaction(source, destination, None, entries)
    final = _snapshot(entries)
    atomic = after_failure["copy_count"] == 0
    idempotent = final["copy_count"] == 1 and final["committed_count"] == 1
    final_document = next(entry["document"] for entry in reversed(entries) if entry["committed"])
    properties = set(map(str, protocol["feature_strata"][int(stratum[1:])]["properties"]))
    oracles = _evaluate(source, final_document, properties)
    oracles["atomicity"] = _oracle("PASS" if atomic else "FAIL", [before, after_failure])
    oracles["idempotence"] = _oracle("PASS" if idempotent else "FAIL", final)
    semantic = _classify(oracles, declarations)
    credential_hash = hashlib.sha256(unb64url(_passkey(source)["credentialId"])).hexdigest()
    sequence_id = f"C3-{stratum}-c{index:03d}-{destination}-{failure_point}"
    common = {
        "protocol_id": protocol["protocol_id"], "campaign_id": "C3", "run_id": "phase6-c3-reference-control-v1",
        "attempt_id": sequence_id, "credential_id_hash": credential_hash, "feature_stratum": stratum,
        "route_id": f"C3-reference-to-{destination}", "seed": protocol["seed"],
        "provider_chain": ["reference", destination], "hop_count": 1, "mutation_id": None,
        "failure_point": failure_point, "exclusion_reason": None,
    }
    sequence = {
        **common,
        "retry_index": 0,
        "execution_status": initial_status,
        "final_execution_status": retry_status,
        "state_before": before,
        "state_after_failure": after_failure,
        "state_after_retry": final,
        "oracles": oracles,
        "declared_losses": sorted(declarations),
        "semantic_class": semantic,
        "normative_class": "NOT_ASSESSED",
        "basic_auth_pass": None,
        "false_reassurance": None,
    }
    events = [
        {**common, "retry_index": 0, "execution_status": initial_status, "state": after_failure},
        {**common, "retry_index": 1, "execution_status": retry_status, "state": final},
    ]
    return sequence, events


def _manifest(
    protocol_path: Path, paths: dict[str, Path], commit: str | None, dirty: bool | None, limitations: list[str]
) -> dict[str, Any]:
    hashes = {
        f"{name}_sha256": hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in paths.items()
        if name != "manifest" and path.exists()
    }
    project_root = protocol_path.resolve().parent.parent
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "passkeytransit_version": __version__,
        "python": sys.version,
        "platform": platform.platform(),
        "source_commit": commit,
        "source_dirty": dirty,
        "protocol_sha256": hashlib.sha256(protocol_path.read_bytes()).hexdigest(),
        "specification_baseline": protocol["specification_baseline"],
        "dependency_lock_sha256": hashlib.sha256((project_root / "requirements.lock").read_bytes()).hexdigest(),
        "browser": "NOT_APPLICABLE",
        "cdp": "NOT_APPLICABLE",
        **hashes,
        "limitations": limitations,
    }


def run_c3_faults(protocol_path: Path, output_dir: Path) -> dict[str, Any]:
    paths = _paths(output_dir, "c3_phase6", ["sequences", "events"])
    validate_protocol(protocol_path)
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    corpus = build_c1_corpus(protocol)
    selected = [item for item in corpus if item[0] % 32 < int(protocol["campaigns"]["C3"]["credentials_per_stratum"])]
    destinations = list(map(str, protocol["campaigns"]["C3"]["destination_profiles"]))
    failure_points = list(map(str, protocol["campaigns"]["C3"]["failure_points"]))
    produced = [
        _c3_sequence(protocol, index, stratum, source, destination, failure_point)
        for index, stratum, source in selected
        for destination in destinations
        for failure_point in failure_points
    ]
    sequences = [item[0] for item in produced]
    events = [event for item in produced for event in item[1]]
    project_root = protocol_path.resolve().parent.parent
    commit, dirty = _git_state(project_root)
    for row in sequences + events:
        row["source_commit"] = commit
        row["environment_id"] = "phase6-fault-control-v1"
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(paths["sequences"], sequences)
    _write_jsonl(paths["events"], events)
    summary = {
        "protocol_id": protocol["protocol_id"],
        "campaign_id": "C3",
        "evidence_class": "synthetic-transaction-fault-control",
        "credential_count": len(selected),
        "failure_sequence_count": len(sequences),
        "event_count": len(events),
        "initial_execution_statuses": dict(Counter(row["execution_status"] for row in sequences)),
        "final_execution_statuses": dict(Counter(row["final_execution_status"] for row in sequences)),
        "atomicity": dict(Counter(row["oracles"]["atomicity"]["status"] for row in sequences)),
        "idempotence": dict(Counter(row["oracles"]["idempotence"]["status"] for row in sequences)),
        "semantic_classes": dict(Counter(row["semantic_class"] for row in sequences)),
        "by_destination_and_failure_point": {
            f"{destination}:{failure_point}": {
                "sequences": sum(row["provider_chain"][-1] == destination and row["failure_point"] == failure_point for row in sequences),
                "atomicity_failures": sum(row["provider_chain"][-1] == destination and row["failure_point"] == failure_point and row["oracles"]["atomicity"]["status"] == "FAIL" for row in sequences),
                "idempotence_failures": sum(row["provider_chain"][-1] == destination and row["failure_point"] == failure_point and row["oracles"]["idempotence"]["status"] == "FAIL" for row in sequences),
            }
            for destination in destinations
            for failure_point in failure_points
        },
        "confirmatory_provider_claims_authorized": False,
    }
    with paths["summary"].open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(summary, indent=2) + "\n")
    manifest = _manifest(
        protocol_path,
        paths,
        commit,
        dirty,
        ["failure behavior is deliberately injected into synthetic provider stores", "results qualify atomicity and retry oracles only"],
    )
    with paths["manifest"].open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(manifest, indent=2) + "\n")
    return {"summary": summary, "manifest": manifest}
