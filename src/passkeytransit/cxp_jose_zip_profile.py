"""Project CXP-shaped ZIP using draft JOSE HPKE-3-KE JWE members.

The JWE crypto mapping is from the JOSE draft. The ZIP/index and transport
binding remain project-defined and are not an external provider exchange.
"""

from __future__ import annotations

import hashlib
import io
import json
import secrets
import zipfile
from typing import Any

from .cxf import assert_valid_passkey_document
from .cxp import CXP_DRAFT_ID, _binding, _canonical, _select_request
from .hpke import public_key_from_jwk
from .jose_hpke_ke import seal_compact
from .model import b64url, unb64url

PROFILE = "passkeytransit-cxp-jose-hpke-zip-v1"
INDEX = "CXP-Export/index.jwe"


def context_digest(request: dict[str, Any], metadata: dict[str, Any]) -> str:
    return b64url(hashlib.sha256(_canonical({
        "draft": CXP_DRAFT_ID, "request": request, "response": metadata,
    })).digest())


def export_zip_jose(request: dict[str, Any], document: dict[str, Any], *, exporter: str) -> dict[str, Any]:
    if not exporter:
        raise ValueError("exporter is required")
    selected = _select_request(request)
    binding = _binding(request)
    assert_valid_passkey_document(document)
    metadata = {"version": 0, "hpke": selected, "archive": "deflate", "exporter": exporter}
    digest = context_digest(request, metadata)
    recipient = public_key_from_jwk(selected["key"])
    identifier = secrets.token_urlsafe(12)
    document_name = f"CXP-Export/documents/{identifier}.jwe"
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        for name, content in ((INDEX, {"documents": [identifier]}), (document_name, document)):
            envelope = {"context": digest, "member": name, "content": content}
            member = zipfile.ZipInfo(name, date_time=(2024, 10, 3, 0, 0, 0))
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, seal_compact(recipient, _canonical(envelope)).encode("ascii"))
    return {
        **metadata,
        "payload": b64url(archive_bytes.getvalue()),
        "_passkeyTransit": {
            "profile": PROFILE,
            "requestId": binding["requestId"],
            "challengeHash": b64url(hashlib.sha256(unb64url(binding["challenge"])).digest()),
        },
    }


def validate_external_decrypted(
    request: dict[str, Any], response: dict[str, Any], decrypted: dict[str, bytes], *, expected_exporter: str
) -> dict[str, Any]:
    """Check outer negotiation and decrypted member binding after external JWE decryption."""
    selected = _select_request(request)
    binding = _binding(request)
    if response.get("version") != 0 or response.get("hpke") != selected or response.get("archive") != "deflate":
        raise ValueError("response negotiation mismatch")
    if response.get("exporter") != expected_exporter:
        raise ValueError("unexpected exporter")
    answer = response.get("_passkeyTransit")
    if not isinstance(answer, dict) or answer.get("profile") != PROFILE or answer.get("requestId") != binding["requestId"]:
        raise ValueError("response request binding mismatch")
    if answer.get("challengeHash") != b64url(hashlib.sha256(unb64url(binding["challenge"])).digest()):
        raise ValueError("response challenge mismatch")
    metadata = {key: response[key] for key in ("version", "hpke", "archive", "exporter")}
    expected_context = context_digest(request, metadata)
    if INDEX not in decrypted or len(decrypted) != 2:
        raise ValueError("unexpected decrypted member set")
    contents: dict[str, Any] = {}
    for name, value in decrypted.items():
        envelope = json.loads(value)
        if not isinstance(envelope, dict) or set(envelope) != {"context", "member", "content"}:
            raise ValueError("invalid JOSE plaintext envelope")
        if envelope["context"] != expected_context or envelope["member"] != name:
            raise ValueError("JOSE member context mismatch")
        contents[name] = envelope["content"]
    index = contents[INDEX]
    if not isinstance(index, dict) or set(index) != {"documents"} or not isinstance(index["documents"], list):
        raise ValueError("invalid index")
    if len(index["documents"]) != 1 or not isinstance(index["documents"][0], str):
        raise ValueError("invalid document identifier")
    name = f"CXP-Export/documents/{index['documents'][0]}.jwe"
    if set(contents) != {INDEX, name}:
        raise ValueError("index/member mismatch")
    document = contents[name]
    assert_valid_passkey_document(document)
    return document
