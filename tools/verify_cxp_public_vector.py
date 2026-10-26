"""Check retained synthetic CXP vector bytes without fetching external source.

The parser and importer outcomes still require run_cxp_public_vector.py with
the pinned cxp_poc2 source. This verifier checks only public input integrity.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "experiments/cxporter_cxp_open/vectors/cxporter-poc2-v1.json"
EXPECTED_ARCHIVE = "60927b038c4d324f0650541475f7b642b6af5bbce3da22501bddfe1bc80a8dd0"
EXPECTED_SOURCE = {
    "cxporter": "96bab31fdadcfd295542bba86b8ec8bd2355294a",
    "cxp_poc2": "fee19d9ac392ffe0153bea8b917aa0a66f12b272",
}


def b64url(value: str) -> bytes:
    if not value or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for char in value):
        raise ValueError("noncanonical base64url")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise ValueError("noncanonical base64url")
    return decoded


def verify(path: Path) -> dict[str, object]:
    vector = json.loads(path.read_text(encoding="utf-8"))
    if vector["vector_version"] != 1 or vector["source_commits"] != EXPECTED_SOURCE:
        raise ValueError("vector version or source pins differ")
    document = vector["cxf"]
    canonical = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()
    if hashlib.sha256(canonical).hexdigest() != vector["cxf_sha256"]:
        raise ValueError("synthetic CXF digest differs")
    if document["accounts"][0]["email"] != "synthetic@example.test":
        raise ValueError("vector is not the designated synthetic account")
    credentials = document["accounts"][0]["items"][0]["credentials"]
    if len(credentials) != 1 or credentials[0]["type"] != "passkey":
        raise ValueError("expected one synthetic passkey")
    if not credentials[0]["rpId"].endswith(".example.test"):
        raise ValueError("unexpected relying-party domain")
    response = vector["response"]
    if "archive" in response or response["hpke"] != {"mode": "base", "kem": 32, "kdf": 1, "aead": 2}:
        raise ValueError("retained response shape differs")
    archive = b64url(response["payload"])
    digest = hashlib.sha256(archive).hexdigest()
    if digest != vector["archive_sha256"] or digest != EXPECTED_ARCHIVE:
        raise ValueError("retained ciphertext archive differs")
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        files = sorted(name for name in zipped.namelist() if not name.endswith("/"))
        if len(files) != 2 or files[0] != "CXP-Export/documents/aXRlbS0w.jwe" or files[1] != "CXP-Export/index.jwe":
            raise ValueError("unexpected ZIP layout")
        index = zipped.read("CXP-Export/index.jwe").decode("ascii")
    protected = json.loads(b64url(index.split(".")[0]))
    if protected["alg"] != "HPKE-Base-X25519-SHA256-AES256GCM":
        raise ValueError("JWE protected algorithm differs")
    if len(b64url(vector["recipient_public_key"])) != 32:
        raise ValueError("recipient public key length differs")
    return {"status": "PASS", "archive_sha256": digest, "jwe_files": len(files),
            "synthetic_passkeys": len(credentials), "scope": "vector integrity and wire structure"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vector", type=Path, default=DEFAULT)
    args = parser.parse_args()
    print(json.dumps(verify(args.vector), sort_keys=True))


if __name__ == "__main__":
    main()
