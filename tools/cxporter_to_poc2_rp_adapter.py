"""Open a fresh synthetic cxporter ZIP for the PoC RP adapter control.

The exported private key is returned only over a local subprocess pipe and
never written to the retained report. This is project-authored import code.
"""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from passkeytransit.cxf import assert_valid_passkey_document  # noqa: E402
from passkeytransit.model import b64url, unb64url  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import x25519  # noqa: E402
from run_cxporter_cxp_passkey import _open_jwe  # noqa: E402


def open_export(binary: Path, source: dict) -> dict:
    assert_valid_passkey_document(source)
    recipient = x25519.X25519PrivateKey.generate()
    public = recipient.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    response = json.loads(subprocess.run(
        [str(binary)], input=json.dumps({"recipientPublicKey": b64url(public), "cxf": source}).encode(),
        capture_output=True, timeout=30, check=True,
    ).stdout)
    archive = unb64url(response["payload"])
    item_id = source["accounts"][0]["items"][0]["id"]
    index_path = "CXP-Export/index.jwe"
    document_path = f"CXP-Export/documents/{item_id}.jwe"
    with zipfile.ZipFile(io.BytesIO(archive)) as package:
        if set(package.namelist()) != {"CXP-Export/", "CXP-Export/documents/", index_path, document_path}:
            raise ValueError("unexpected ZIP members")
        if package.testzip() is not None:
            raise ValueError("damaged ZIP")
        index_jwe = package.read(index_path)
        document_jwe = package.read(document_path)
    _, index_bytes = _open_jwe(index_jwe, recipient, 0)
    _, document_bytes = _open_jwe(document_jwe, recipient, 1)
    index = json.loads(index_bytes)
    item = json.loads(document_bytes)
    if index["accounts"][0]["items"][0]["id"] != item["id"]:
        raise ValueError("index/document ID differs")
    recovered = json.loads(json.dumps(source))
    recovered["accounts"][0]["items"][0] = item
    assert_valid_passkey_document(recovered)
    return {"recovered": recovered, "archive_sha256": hashlib.sha256(archive).hexdigest(),
            "response_has_archive": "archive" in response}


def main() -> None:
    binary = Path(sys.argv[1]).resolve()
    print(json.dumps(open_export(binary, json.load(sys.stdin))))


if __name__ == "__main__":
    main()
