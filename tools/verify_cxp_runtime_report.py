"""Check the scoped output from the pinned Bitwarden Rust type probe."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def verify(path: Path) -> dict[str, object]:
    report = json.loads(path.read_text(encoding="utf-8"))
    expected = {
        "source_commit": "32da4c8b0a4abdd0b46fae79c31e0fdb50150396",
        "request_parse": "PASS",
        "response_parse": "PASS",
        "request_fields_dropped_on_roundtrip": ["archive", "mode"],
        "response_fields_dropped_on_roundtrip": ["archive"],
        "draft_valid_version_256_rejected": True,
        "hpke_jwe_decryption": "NOT_EVALUABLE",
        "provider_interoperability": "NOT_EVALUABLE",
    }
    for key, value in expected.items():
        if report.get(key) != value:
            raise ValueError(f"unexpected Rust type probe result: {key}")
    return report


if __name__ == "__main__":
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))
