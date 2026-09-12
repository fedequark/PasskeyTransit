from __future__ import annotations

import copy
import csv
import hashlib
import json
import platform
import random
import subprocess
import sys
from collections import Counter
from itertools import combinations
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from . import __version__
from .cxf import build_passkey_document, inflate_large_blob, validate_passkey_document
from .cxp import ReplayCache, create_import_session, export_cxf, import_cxf
from .model import b64url, generate_synthetic_passkey, unb64url
from .protocol import validate_protocol


ORACLES = (
    "cxf_structure",
    "credential_id",
    "rp_id",
    "user_handle",
    "public_key",
    "webauthn_assertion",
    "uv",
    "prf_uv",
    "prf_no_uv",
    "large_blob",
    "cred_blob",
    "payments_marker",
    "idempotence",
    "atomicity",
    "custody_ground_truth",
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _evidence(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _oracle(status: str, evidence: object, requirement_ids: list[str] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": status, "evidence_ref": _evidence(evidence)}
    if requirement_ids:
        result["requirement_ids"] = requirement_ids
    return result


def build_c1_corpus(protocol: dict[str, Any]) -> list[tuple[int, str, dict[str, Any]]]:
    seed = int(protocol["seed"])
    per_stratum = int(protocol["campaigns"]["C1"]["credentials_per_stratum"])
    corpus: list[tuple[int, str, dict[str, Any]]] = []
    for stratum_index, stratum in enumerate(protocol["feature_strata"]):
        stratum_id = str(stratum["id"])
        for offset in range(per_stratum):
            index = stratum_index * per_stratum + offset
            base = generate_synthetic_passkey(seed, index).evolve(prf_secret=None, large_blob=None)
            properties = set(map(str, stratum["properties"]))
            if "large_blob" in properties:
                base = base.evolve(large_blob=b"phase5-large-blob:" + hashlib.sha512(base.credential_id).digest())
            hmac_with_uv = hashlib.sha256(base.credential_id + b":hmac-with-uv").digest() if "prf_uv" in properties else None
            hmac_without_uv = hashlib.sha256(base.credential_id + b":hmac-without-uv").digest() if "prf_uv" in properties else None
            if "prf_no_uv" in properties:
                hmac_with_uv = hashlib.sha256(base.credential_id + b":hmac-with-uv").digest()
                hmac_without_uv = hashlib.sha256(base.credential_id + b":hmac-without-uv").digest()
            document = build_passkey_document(
                base,
                timestamp=1789167600,
                account_id=hashlib.sha256(base.credential_id + b":account").digest()[:16],
                item_id=hashlib.sha256(base.credential_id + b":item").digest()[:16],
                hmac_with_uv=hmac_with_uv,
                hmac_without_uv=hmac_without_uv,
                cred_blob=(b"phase5-cred-blob:" + base.credential_id if "cred_blob" in properties else None),
                payments=True if "payments_marker" in properties else None,
            )
            if "unknown_optional_member" in properties:
                document["accounts"][0]["items"][0]["credentials"][0]["futureOptionalMember"] = {
                    "opaque": b64url(hashlib.sha256(base.credential_id + b":future").digest())
                }
            corpus.append((index, stratum_id, document))
    return corpus


def _passkey(document: dict[str, Any]) -> dict[str, Any]:
    return document["accounts"][0]["items"][0]["credentials"][0]


def _apply_profile(document: dict[str, Any], profile: str) -> tuple[dict[str, Any], set[str]]:
    migrated = copy.deepcopy(document)
    extensions = _passkey(migrated).get("fido2Extensions")
    declared: set[str] = set()
    if not isinstance(extensions, dict):
        return migrated, declared
    if profile == "compatible-lossy":
        if "hmacCredentials" in extensions:
            extensions.pop("hmacCredentials")
            declared.update({"prf_uv", "prf_no_uv"})
        if "credBlob" in extensions:
            extensions.pop("credBlob")
            declared.add("cred_blob")
    elif profile == "legacy":
        _passkey(migrated).pop("fido2Extensions", None)
    elif profile not in {"reference", "strict"}:
        raise ValueError(f"unknown provider profile: {profile}")
    if extensions == {}:
        _passkey(migrated).pop("fido2Extensions", None)
    return migrated, declared


def _transport(document: dict[str, Any], source: str, destination: str) -> dict[str, Any]:
    session = create_import_session(f"{destination}.control.example.test")
    response = export_cxf(session.request, document, exporter=f"{source}.control.example.test")
    return import_cxf(
        session,
        response,
        expected_exporter=f"{source}.control.example.test",
        replay_cache=ReplayCache(),
    )


def _optional_bytes(passkey: dict[str, Any], member: str) -> bytes | None:
    extensions = passkey.get("fido2Extensions")
    if not isinstance(extensions, dict) or member not in extensions:
        return None
    value = extensions[member]
    return unb64url(str(value)) if isinstance(value, str) else None


def _key_public_der(passkey: dict[str, Any]) -> bytes:
    key = serialization.load_der_private_key(unb64url(passkey["key"]), password=None)
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _evaluate(source: dict[str, Any], migrated: dict[str, Any], properties: set[str]) -> dict[str, dict[str, Any]]:
    source_key, migrated_key = _passkey(source), _passkey(migrated)
    findings = validate_passkey_document(migrated)
    results: dict[str, dict[str, Any]] = {
        "cxf_structure": _oracle("PASS" if not any(f.severity == "error" for f in findings) else "FAIL", [f.__dict__ for f in findings]),
        "credential_id": _oracle("PASS" if source_key["credentialId"] == migrated_key["credentialId"] else "FAIL", [source_key["credentialId"], migrated_key["credentialId"]]),
        "rp_id": _oracle("PASS" if source_key["rpId"] == migrated_key["rpId"] else "FAIL", [source_key["rpId"], migrated_key["rpId"]]),
        "user_handle": _oracle("PASS" if source_key["userHandle"] == migrated_key["userHandle"] else "FAIL", [source_key["userHandle"], migrated_key["userHandle"]]),
        "public_key": _oracle("PASS" if _key_public_der(source_key) == _key_public_der(migrated_key) else "FAIL", [hashlib.sha256(_key_public_der(source_key)).hexdigest(), hashlib.sha256(_key_public_der(migrated_key)).hexdigest()]),
        "webauthn_assertion": _oracle("NOT_EVALUABLE", "no browser ceremony in phase-5 control runner"),
        "uv": _oracle("NOT_EVALUABLE", "no browser ceremony in phase-5 control runner"),
        "idempotence": _oracle("NOT_APPLICABLE", "C1 campaign"),
        "atomicity": _oracle("NOT_APPLICABLE", "C1 campaign"),
        "custody_ground_truth": _oracle("PASS", "instrumented in-process provider chain"),
    }
    source_ext = source_key.get("fido2Extensions", {})
    migrated_ext = migrated_key.get("fido2Extensions", {})
    for name in ("prf_uv", "prf_no_uv"):
        if name not in properties:
            results[name] = _oracle("NOT_APPLICABLE", name)
        elif not isinstance(migrated_ext, dict) or "hmacCredentials" not in migrated_ext:
            results[name] = _oracle("FAIL", "required HMAC credentials absent")
        else:
            results[name] = _oracle("NOT_EVALUABLE", "HMAC material present but browser PRF output unavailable")
    if "large_blob" not in properties:
        results["large_blob"] = _oracle("NOT_APPLICABLE", "largeBlob absent at source")
    elif not isinstance(migrated_ext, dict) or "largeBlob" not in migrated_ext:
        results["large_blob"] = _oracle("FAIL", "required largeBlob absent")
    else:
        source_blob = inflate_large_blob(source_key)
        migrated_blob = inflate_large_blob(migrated_key)
        status = "NOT_EVALUABLE" if source_blob == migrated_blob else "FAIL"
        results["large_blob"] = _oracle(status, [hashlib.sha256(source_blob or b"").hexdigest(), hashlib.sha256(migrated_blob or b"").hexdigest()])
    if "cred_blob" not in properties:
        results["cred_blob"] = _oracle("NOT_APPLICABLE", "credBlob absent at source")
    else:
        before, after = _optional_bytes(source_key, "credBlob"), _optional_bytes(migrated_key, "credBlob")
        status = "NOT_EVALUABLE" if before is not None and before == after else "FAIL"
        results["cred_blob"] = _oracle(status, [hashlib.sha256(before or b"").hexdigest(), hashlib.sha256(after or b"").hexdigest()])
    if "payments_marker" not in properties:
        results["payments_marker"] = _oracle("NOT_APPLICABLE", "payments marker absent at source")
    else:
        before = source_ext.get("payments") if isinstance(source_ext, dict) else None
        after = migrated_ext.get("payments") if isinstance(migrated_ext, dict) else None
        results["payments_marker"] = _oracle("PASS" if before is True and after is True else "FAIL", [before, after])
    return {name: results[name] for name in ORACLES}


def _classify(oracles: dict[str, dict[str, Any]], declared_losses: set[str]) -> str:
    failures = {name for name, result in oracles.items() if result["status"] == "FAIL"}
    if failures:
        return "DEGRADED_VISIBLE" if failures <= declared_losses else "DEGRADED_SILENT"
    if any(result["status"] == "NOT_EVALUABLE" for result in oracles.values()):
        return "NOT_EVALUABLE"
    return "PASS"


def _attempt(
    protocol: dict[str, Any], index: int, stratum: str, source: dict[str, Any], route: dict[str, Any], repetition: int
) -> dict[str, Any]:
    current = copy.deepcopy(source)
    declared_losses: set[str] = set()
    chain = list(map(str, route["chain"]))
    for source_provider, destination in zip(chain, chain[1:]):
        current = _transport(current, source_provider, destination)
        current, declarations = _apply_profile(current, destination)
        declared_losses.update(declarations)
    properties = set(map(str, protocol["feature_strata"][int(stratum[1:])]["properties"]))
    oracles = _evaluate(source, current, properties)
    semantic_class = _classify(oracles, declared_losses)
    credential_hash = hashlib.sha256(unb64url(_passkey(source)["credentialId"])).hexdigest()
    return {
        "protocol_id": protocol["protocol_id"],
        "campaign_id": "C1",
        "run_id": f"phase5-reference-control-r{repetition + 1}",
        "attempt_id": f"C1-r{repetition + 1}-c{index:03d}-{route['id']}",
        "credential_id_hash": credential_hash,
        "feature_stratum": stratum,
        "route_id": route["id"],
        "seed": protocol["seed"],
        "provider_chain": chain,
        "hop_count": len(chain) - 1,
        "mutation_id": None,
        "failure_point": None,
        "retry_index": 0,
        "execution_status": "IMPORTED",
        "oracles": oracles,
        "declared_losses": sorted(declared_losses),
        "semantic_class": semantic_class,
        "normative_class": "NOT_ASSESSED",
        "basic_auth_pass": None,
        "false_reassurance": None,
        "exclusion_reason": None,
    }


def _bootstrap(rows: list[dict[str, Any]], numerator: Any, denominator: Any, seed: int) -> dict[str, Any]:
    clusters: dict[str, tuple[int, int]] = {}
    for credential in {str(row["credential_id_hash"]) for row in rows}:
        selected = [row for row in rows if row["credential_id_hash"] == credential]
        clusters[credential] = (sum(bool(numerator(row)) for row in selected), sum(bool(denominator(row)) for row in selected))
    numerator_count = sum(bool(numerator(row)) for row in rows)
    denominator_count = sum(bool(denominator(row)) for row in rows)
    result: dict[str, Any] = {"numerator": numerator_count, "denominator": denominator_count, "estimate": None, "ci95": None}
    if denominator_count == 0:
        return result
    result["estimate"] = numerator_count / denominator_count
    rng = random.Random(seed)
    values = list(clusters.values())
    samples: list[float] = []
    for _ in range(2000):
        drawn = [values[rng.randrange(len(values))] for _ in values]
        den = sum(value[1] for value in drawn)
        if den:
            samples.append(sum(value[0] for value in drawn) / den)
    samples.sort()
    result["ci95"] = [samples[int(0.025 * (len(samples) - 1))], samples[int(0.975 * (len(samples) - 1))]]
    return result


def _git_state(project_root: Path) -> tuple[str | None, bool | None]:
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=project_root, text=True).strip()
        dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=project_root, text=True).strip())
        return commit, dirty
    except Exception:
        return None, None


def _paired_route_comparisons(rows: list[dict[str, Any]], protocol: dict[str, Any]) -> list[dict[str, Any]]:
    routes = {str(route["id"]): list(map(str, route["chain"])) for route in protocol["routes"]}
    index = {(row["run_id"], row["credential_id_hash"], row["route_id"]): row for row in rows}
    comparisons: list[dict[str, Any]] = []
    by_destination: dict[str, list[str]] = {}
    for route_id, chain in routes.items():
        by_destination.setdefault(chain[-1], []).append(route_id)
    run_credentials = sorted({(str(row["run_id"]), str(row["credential_id_hash"])) for row in rows})
    for destination, route_ids in sorted(by_destination.items()):
        for left_id, right_id in combinations(sorted(route_ids), 2):
            semantic_discordant = 0
            oracle_discordant = 0
            pair_count = 0
            for run_id, credential in run_credentials:
                left = index[(run_id, credential, left_id)]
                right = index[(run_id, credential, right_id)]
                pair_count += 1
                semantic_discordant += left["semantic_class"] != right["semantic_class"]
                oracle_discordant += any(
                    left["oracles"][name]["status"] != right["oracles"][name]["status"] for name in ORACLES
                )
            comparisons.append(
                {
                    "destination": destination,
                    "left_route": left_id,
                    "right_route": right_id,
                    "paired_attempts": pair_count,
                    "semantic_discordant": semantic_discordant,
                    "any_oracle_discordant": oracle_discordant,
                }
            )
    return comparisons


def run_c1_reference_control(protocol_path: Path, output_dir: Path) -> dict[str, Any]:
    raw_path = output_dir / "c1_phase5_attempts.jsonl"
    csv_path = output_dir / "c1_phase5_derived.csv"
    summary_path = output_dir / "c1_phase5_summary.json"
    manifest_path = output_dir / "c1_phase5_manifest.json"
    existing = [path for path in (raw_path, csv_path, summary_path, manifest_path) if path.exists()]
    if existing:
        raise FileExistsError(f"campaign output is immutable; choose a new directory: {existing[0]}")
    validate_protocol(protocol_path)
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    corpus = build_c1_corpus(protocol)
    routes = {route["id"]: route for route in protocol["routes"]}
    registered_routes = protocol["campaigns"]["C1"]["route_ids"]
    base_order = [(index, stratum, source, routes[route_id]) for index, stratum, source in corpus for route_id in registered_routes]
    random.Random(int(protocol["seed"])).shuffle(base_order)
    rows: list[dict[str, Any]] = []
    for repetition in range(int(protocol["campaigns"]["C1"]["repetitions"])):
        rows.extend(_attempt(protocol, index, stratum, source, route, repetition) for index, stratum, source, route in base_order)
    project_root = protocol_path.resolve().parent.parent
    commit, dirty = _git_state(project_root)
    for row in rows:
        row["source_commit"] = commit
        row["environment_id"] = "phase5-reference-policy-control-v1"
    output_dir.mkdir(parents=True, exist_ok=True)
    with raw_path.open("x", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    flat_rows = [
        {
            "attempt_id": row["attempt_id"], "credential_id_hash": row["credential_id_hash"],
            "feature_stratum": row["feature_stratum"], "route_id": row["route_id"],
            "repetition": row["run_id"], "execution_status": row["execution_status"],
            "semantic_class": row["semantic_class"], "normative_class": row["normative_class"],
            **{name: row["oracles"][name]["status"] for name in ORACLES},
        }
        for row in rows
    ]
    with csv_path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(flat_rows[0]))
        writer.writeheader()
        writer.writerows(flat_rows)
    seed = int(protocol["seed"])
    estimands = {
        "preserving_migration_yield": _bootstrap(rows, lambda row: row["semantic_class"] == "PASS", lambda row: True, seed + 1),
        "conditional_semantic_preservation": _bootstrap(rows, lambda row: row["semantic_class"] == "PASS", lambda row: row["execution_status"] == "IMPORTED", seed + 2),
        "silent_degradation_rate": _bootstrap(rows, lambda row: row["semantic_class"] == "DEGRADED_SILENT", lambda row: row["execution_status"] == "IMPORTED", seed + 3),
        "false_reassurance_rate": _bootstrap(rows, lambda row: row["false_reassurance"] is True, lambda row: row["basic_auth_pass"] is True, seed + 4),
    }
    normalized = lambda row: _canonical({key: value for key, value in row.items() if key not in {"run_id", "attempt_id"}})
    per_rep = len(base_order)
    repeat_equivalent = all(normalized(rows[i]) == normalized(rows[i + per_rep]) for i in range(per_rep))
    summary = {
        "protocol_id": protocol["protocol_id"],
        "campaign_id": "C1",
        "evidence_class": "synthetic-reference-policy-control",
        "credential_count": len(corpus),
        "route_count": len(registered_routes),
        "repetitions": 2,
        "attempt_count": len(rows),
        "execution_statuses": dict(Counter(row["execution_status"] for row in rows)),
        "semantic_classes": dict(Counter(row["semantic_class"] for row in rows)),
        "oracle_statuses": {name: dict(Counter(row["oracles"][name]["status"] for row in rows)) for name in ORACLES},
        "estimands": estimands,
        "paired_route_comparisons": _paired_route_comparisons(rows, protocol),
        "repeat_equivalent": repeat_equivalent,
        "confirmatory_provider_claims_authorized": False,
    }
    with summary_path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(summary, indent=2) + "\n")
    manifest = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "passkeytransit_version": __version__,
        "python": sys.version,
        "platform": platform.platform(),
        "source_commit": commit,
        "source_dirty": dirty,
        "protocol_sha256": hashlib.sha256(protocol_path.read_bytes()).hexdigest(),
        "raw_sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
        "derived_sha256": hashlib.sha256(csv_path.read_bytes()).hexdigest(),
        "summary_sha256": hashlib.sha256(summary_path.read_bytes()).hexdigest(),
        "limitations": [
            "synthetic reference policies are not commercial providers",
            "no browser ceremony: WebAuthn, UV, positive PRF and positive blob preservation remain NOT_EVALUABLE",
            "this is harness qualification, not confirmatory provider evidence",
        ],
    }
    with manifest_path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(manifest, indent=2) + "\n")
    return {"summary": summary, "manifest": manifest}
