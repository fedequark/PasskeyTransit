"""Generate or replay a retained synthetic cxporter -> cxp_poc2 wire vector."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from passkeytransit.cxf import build_passkey_document
from passkeytransit.model import generate_synthetic_passkey

ROOT = Path(__file__).resolve().parents[1]
GO_COMMIT = "96bab31fdadcfd295542bba86b8ec8bd2355294a"
TS_COMMIT = "fee19d9ac392ffe0153bea8b917aa0a66f12b272"
SCHEMA_ERROR = "CxpValidationError: Malformed ExportResponse: $.archive: Invalid input: expected string, received undefined"
JWE_ERROR = 'JweError: JWE decryption failed: "alg" (Algorithm) Header Parameter value not allowed'


def revision(path: Path) -> str:
    return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()


def invoke(source: Path, mode: str, arg: Path, document: dict | None = None) -> dict:
    pnpm = shutil.which("pnpm")
    if pnpm is None:
        raise FileNotFoundError("pnpm is required for the pinned TypeScript importer")
    process = subprocess.run(
        [pnpm, "exec", "tsx", "src/cli/pt-vector.ts", mode, str(arg.resolve())],
        cwd=source,
        input=json.dumps(document) if document is not None else None,
        text=True,
        capture_output=True,
        timeout=90,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(process.stderr.strip())
    return json.loads(process.stdout)


def run(ts_source: Path, vector: Path, binary: Path | None) -> dict:
    ts_source, vector = ts_source.resolve(), vector.resolve()
    if revision(ts_source) != TS_COMMIT:
        raise ValueError("second importer revision differs from pin")
    shutil.copyfile(
        ROOT / "interop/cxp_poc2_cross_probe/pt-vector.ts",
        ts_source / "src/cli/pt-vector.ts",
    )
    if binary is not None:
        go_source = binary.resolve().parent / "vendor_cxporter"
        if revision(go_source) != GO_COMMIT:
            raise ValueError("exporter revision differs from pin")
        document = build_passkey_document(
            generate_synthetic_passkey(20261026, 91),
            timestamp=1_700_000_000,
            hmac_with_uv=hashlib.sha256(b"public-cxp-vector:uv").digest(),
            hmac_without_uv=hashlib.sha256(b"public-cxp-vector:no-uv").digest(),
        )
        generated = invoke(ts_source, "generate", binary, document)
        if generated["source_commits"] != {"cxporter": GO_COMMIT, "cxp_poc2": TS_COMMIT}:
            raise ValueError("generated vector has unexpected source revisions")
        vector.parent.mkdir(parents=True, exist_ok=True)
        vector.write_text(json.dumps(generated, indent=2) + "\n", encoding="utf-8")
    observed = invoke(ts_source, "replay", vector)
    if observed["vector_version"] != 1:
        raise ValueError("vector version differs")
    if observed["response_has_archive"] is not False or observed["schema_error"] != SCHEMA_ERROR:
        raise ValueError("full response parser no longer rejects missing archive")
    if observed["patched_schema_error"]:
        raise ValueError("response parser rejected the archive-field control")
    if observed["index_jwe_alg"] != "HPKE-Base-X25519-SHA256-AES256GCM":
        raise ValueError("index JWE algorithm differs")
    if observed["payload_error"] != JWE_ERROR:
        raise ValueError("second importer no longer rejects the JWE algorithm")
    if observed["archive_file_count"] != 2:
        raise ValueError("unexpected JWE file count")
    return observed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ts-source", type=Path, required=True)
    parser.add_argument("--vector", type=Path, required=True)
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.ts_source, args.vector, args.binary), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
