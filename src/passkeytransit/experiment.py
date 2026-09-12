from __future__ import annotations

import csv
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .model import generate_synthetic_passkey
from .oracles import evaluate
from .providers import migrate_route


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def run_pilot(config_path: Path, output_dir: Path) -> dict[str, object]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    seed = int(config["seed"])
    credential_count = int(config["credential_count"])
    routes = config["routes"]
    if not isinstance(routes, list) or not all(isinstance(route, list) for route in routes):
        raise ValueError("routes must be a list of provider-name lists")

    rows: list[dict[str, object]] = []
    for index in range(credential_count):
        source = generate_synthetic_passkey(seed, index)
        for route_index, route in enumerate(routes):
            migrated = migrate_route(source, [str(name) for name in route])
            checks = evaluate(source, migrated)
            rows.append(
                {
                    "credential_index": index,
                    "route_index": route_index,
                    "route": ">".join(str(name) for name in route),
                    **checks,
                    "all_preserved": all(checks.values()),
                }
            )

    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "pilot_v0.1_observations.csv"
    json_path = output_dir / "pilot_v0.1_summary.json"
    manifest_path = output_dir / "pilot_v0.1_manifest.json"

    fieldnames = list(rows[0]) if rows else []
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    oracle_names = [
        "credential_id",
        "rp_id",
        "user_handle",
        "public_key",
        "signature",
        "prf",
        "large_blob",
        "all_preserved",
    ]
    summary = {
        "experiment_id": config["experiment_id"],
        "evidence_class": "synthetic-policy-control",
        "credential_count": credential_count,
        "route_count": len(routes),
        "observation_count": len(rows),
        "preserved_counts": {
            name: sum(bool(row[name]) for row in rows) for name in oracle_names
        },
    }
    json_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    reproducibility_payload = {"config": config, "rows": rows, "summary": summary}
    manifest = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "passkeytransit_version": __version__,
        "python": sys.version,
        "platform": platform.platform(),
        "config_sha256": hashlib.sha256(_canonical_json(config)).hexdigest(),
        "result_sha256": hashlib.sha256(
            _canonical_json(reproducibility_payload)
        ).hexdigest(),
        "limitations": [
            "synthetic credentials and provider policies",
            "experimental CXF subset, not full CXF conformance",
            "PRF control is not a WebAuthn browser ceremony",
            "no CXP or HPKE transport",
        ],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return {"summary": summary, "manifest": manifest}

