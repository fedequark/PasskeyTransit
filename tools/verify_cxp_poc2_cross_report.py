"""Check retained results of the two-open-implementation rejection replay.

The public report contains no ciphertext; rerun the pinned source workflow to
confirm the observed import failure, not just the report's consistency.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

GO_COMMIT = "96bab31fdadcfd295542bba86b8ec8bd2355294a"
TS_COMMIT = "fee19d9ac392ffe0153bea8b917aa0a66f12b272"
EXPECTED_ERROR = 'JweError: JWE decryption failed: "alg" (Algorithm) Header Parameter value not allowed'


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def verify(report: dict) -> dict:
    root = Path(__file__).resolve().parents[1]
    adapter = root / "interop/cxp_poc2_cross_probe/pt-cross.ts"
    require(report["source_commits"] == {"cxporter": GO_COMMIT, "cxp_poc2": TS_COMMIT},
            "external source pins differ")
    require(report["adapter_sha256"] == hashlib.sha256(adapter.read_bytes()).hexdigest(),
            "adapter hash differs")
    require(report["status"] == "EXPECTED_REJECTION" and
            report["interoperability"] == "FAIL_JWE_ALGORITHM_MISMATCH",
            "cross-implementation outcome differs")
    require(len(report["runs"]) == 2, "wrong repetition count")
    for repetition, run in enumerate(report["runs"]):
        require(run["repetition"] == repetition, "wrong repetition index")
        require(run["second_source_commit"] == TS_COMMIT, "second source pin differs")
        require(run["self_import_items"] == 1 and run["self_import_passkey_state_preserved"] is True,
                "second importer's own positive control failed")
        require(run["cross_import_rejected"] is True and run["cross_import_error"] == EXPECTED_ERROR,
                "cross-import rejection differs")
        require(run["cxporter_jwe_alg"] == "HPKE-Base-X25519-SHA256-AES256GCM",
                "external JWE algorithm differs")
        require(run["response_archive_field_present"] is False, "response schema finding differs")
        digest = run["cxporter_archive_sha256"]
        require(len(digest) == 64 and all(c in "0123456789abcdef" for c in digest),
                "invalid archive digest")
    return {"repetitions": 2, "second_importer_self_tests": 2,
            "cross_import_expected_rejections": 2, "execution_replay_required": True}


def negative_controls(report: dict) -> None:
    for field, value in (("cross_import_rejected", False), ("cross_import_error", "")):
        changed = copy.deepcopy(report)
        changed["runs"][0][field] = value
        try:
            verify(changed)
        except AssertionError:
            continue
        raise AssertionError(f"verifier accepted modified {field}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    result = verify(report)
    negative_controls(report)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
