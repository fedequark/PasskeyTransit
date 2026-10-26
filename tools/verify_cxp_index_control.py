"""Check the retained index-layout diagnostic report and source binding.

This checks report consistency. The importer rejection itself is reproducible
only by running the pinned external source through run_cxp_index_control.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from extract_cxp_public_index import extract

ROOT = Path(__file__).resolve().parents[1]
GO_COMMIT = "96bab31fdadcfd295542bba86b8ec8bd2355294a"
TS_COMMIT = "fee19d9ac392ffe0153bea8b917aa0a66f12b272"
ERROR = "CxpPayloadError: index.jwe is not {header, documents}"


def verify(root: Path, report_path: Path) -> dict:
    vector_path = root / "experiments/cxporter_cxp_open/vectors/cxporter-poc2-v1.json"
    index_path = root / "experiments/cxporter_cxp_open/vectors/cxporter-index-v1.json"
    expected_index = extract(vector_path)
    if json.loads(index_path.read_text(encoding="utf-8")) != expected_index:
        raise ValueError("retained decrypted index differs from source ciphertext")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    adapter = root / "interop/cxp_poc2_cross_probe/pt-index-control.ts"
    if report["source_commits"] != {"cxporter": GO_COMMIT, "cxp_poc2": TS_COMMIT}:
        raise ValueError("source revisions differ")
    if report["adapter_sha256"] != hashlib.sha256(adapter.read_bytes()).hexdigest():
        raise ValueError("adapter digest differs")
    if report["index_sha256"] != expected_index["index_sha256"]:
        raise ValueError("index plaintext digest differs")
    if report["status"] != "EXPECTED_REJECTION_AFTER_ADAPTER_TRANSFORMATION":
        raise ValueError("report classification differs")
    observation = report["observation"]
    if observation["source_archive_sha256"] != expected_index["source_archive_sha256"]:
        raise ValueError("source archive digest differs")
    if observation["positive_self_import_items"] != 1 or observation["importer_error"] != ERROR:
        raise ValueError("positive control or index rejection differs")
    if observation["replacement_index_jwe_alg"] != "dir":
        raise ValueError("replacement JWE profile differs")
    digest = observation["transformed_archive_sha256"]
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError("transformed archive digest is invalid")
    if "not original cxporter ciphertext" not in report["limitation"]:
        raise ValueError("report omits transformation limit")
    return {"status": "PASS", "index_sha256": expected_index["index_sha256"],
            "importer_error": ERROR, "scope": "report consistency; pinned-source replay required"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--report", type=Path, default=ROOT / "experiments/cxporter_cxp_open/index_control.json")
    args = parser.parse_args()
    print(json.dumps(verify(args.root, args.report), sort_keys=True))


if __name__ == "__main__":
    main()
