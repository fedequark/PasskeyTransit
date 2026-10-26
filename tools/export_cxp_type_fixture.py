"""Freeze the deterministic synthetic CXP objects for the Rust type probe."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from passkeytransit.cxp_wire_probe import synthetic_fixture  # noqa: E402


if __name__ == "__main__":
    request, response = synthetic_fixture()
    target = ROOT / "experiments/cxp_external_schema/fixture.json"
    target.write_text(json.dumps({"request": request, "response": response}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(target)
