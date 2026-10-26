"""Check the scoped result from the pinned Go CXP type parser."""

import json
import sys
from pathlib import Path


def verify(path: Path) -> dict:
    report = json.loads(path.read_text(encoding="utf-8"))
    expected = {
        "source_commit": "94659f317ac62470a149cb3ecb769ed5d03d18a1",
        "request_parse": "PASS",
        "response_parse": "PASS",
        "request_fields_dropped_on_roundtrip": ["mode"],
        "response_fields_dropped_on_roundtrip": [],
        "draft_width_version_256_rejected": True,
        "hpke_jwe_decryption": "NOT_EVALUABLE",
        "provider_interoperability": "NOT_EVALUABLE",
    }
    for key, value in expected.items():
        if report.get(key) != value:
            raise ValueError(f"unexpected Go type probe result: {key}")
    return report


if __name__ == "__main__":
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))
