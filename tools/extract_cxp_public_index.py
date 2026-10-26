"""Extract a synthetic cxporter index for an isolated importer layout control.

The fixed X25519 key is a PUBLIC TEST KEY derived by the pinned cxp_poc2
library from the public vector label. Never use it with real credentials.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from passkeytransit.model import b64url, unb64url
from run_cxporter_cxp_passkey import _open_jwe
from verify_cxp_public_vector import verify

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VECTOR = ROOT / "experiments/cxporter_cxp_open/vectors/cxporter-poc2-v1.json"
DEFAULT_OUT = ROOT / "experiments/cxporter_cxp_open/vectors/cxporter-index-v1.json"
TEST_PRIVATE_B64URL = "Z5fx-ykf3da0zecHuSApUeXVz5B-iljALabfQP8At2I"


def extract(vector_path: Path) -> dict:
    verify(vector_path)
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    private = x25519.X25519PrivateKey.from_private_bytes(unb64url(TEST_PRIVATE_B64URL))
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if b64url(public) != vector["recipient_public_key"]:
        raise ValueError("public test key differs from vector recipient")
    archive = unb64url(vector["response"]["payload"])
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        header, plaintext = _open_jwe(zipped.read("CXP-Export/index.jwe"), private, 0)
    if header["alg"] != "HPKE-Base-X25519-SHA256-AES256GCM":
        raise ValueError("unexpected source JWE algorithm")
    index = json.loads(plaintext)
    if not isinstance(index.get("accounts"), list) or "header" in index or "documents" in index:
        raise ValueError("source index no longer exposes the expected layout contrast")
    return {
        "vector_version": 1,
        "classification": "decrypted synthetic cxporter index; not the original JWE",
        "source_archive_sha256": hashlib.sha256(archive).hexdigest(),
        "index_sha256": hashlib.sha256(plaintext).hexdigest(),
        "recipient_public_key": vector["recipient_public_key"],
        "index": index,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vector", type=Path, default=DEFAULT_VECTOR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    result = extract(args.vector)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"source_archive_sha256": result["source_archive_sha256"],
                      "index_sha256": result["index_sha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
