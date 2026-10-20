"""Structural probe of the public CXP 2024 working-draft envelope.

This module deliberately does not implement an HPKE-to-JWE mapping: the
working draft gives no complete mapping or encapsulation field. A PASS here
means only that the visible JSON, ZIP and JWE shapes meet this probe's checks.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import zipfile
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class WireShapeError(ValueError):
    pass


MAX_ZIP_BYTES = 1024 * 1024
MAX_ENTRIES = 64
MAX_ENTRY_BYTES = 256 * 1024
DOCUMENT_NAME = re.compile(r"^CXP-Export/documents/[A-Za-z0-9_-]{1,64}\.jwe$")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise WireShapeError("invalid base64url")
    try:
        result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise WireShapeError("invalid base64url") from exc
    if _b64(result) != value:
        raise WireShapeError("noncanonical base64url")
    return result


def _object(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WireShapeError(f"{name} must be an object")
    return value


def _suite(value: object) -> dict[str, Any]:
    suite = _object(value, "HPKE parameter set")
    if suite.get("mode") not in {"base", "psk", "auth", "auth-psk"}:
        raise WireShapeError("unsupported HPKE mode")
    for name in ("kem", "kdf", "aead"):
        if type(suite.get(name)) is not int or not 0 <= suite[name] <= 65535:
            raise WireShapeError(f"invalid {name} identifier")
    key = _object(suite.get("key"), "JWK")
    if not all(isinstance(key.get(k), str) and key[k] for k in ("kty", "crv", "x")):
        raise WireShapeError("incomplete public JWK")
    if "d" in key:
        raise WireShapeError("private JWK material in request")
    _unb64(key["x"])
    return suite


def validate_request(request: object) -> dict[str, Any]:
    request = _object(request, "request")
    if type(request.get("version")) is not int or not 0 <= request["version"] <= 65535:
        raise WireShapeError("invalid request version")
    if request.get("mode") not in {"direct", "indirect", "self"}:
        raise WireShapeError("invalid response mode")
    if not isinstance(request.get("importer"), str) or not request["importer"]:
        raise WireShapeError("missing importer")
    if not isinstance(request.get("hpke"), list) or not request["hpke"]:
        raise WireShapeError("missing HPKE offers")
    for candidate in request["hpke"]:
        _suite(candidate)
    if not isinstance(request.get("archive"), list) or not request["archive"]:
        raise WireShapeError("missing archive offers")
    if not all(isinstance(a, str) and a for a in request["archive"]):
        raise WireShapeError("invalid archive offer")
    for name in ("credentialTypes", "knownExtensions"):
        if name in request and (
            not isinstance(request[name], list)
            or not all(isinstance(v, str) for v in request[name])
        ):
            raise WireShapeError(f"invalid {name}")
    return request


def _jwe_shape(data: bytes) -> None:
    try:
        parts = data.decode("ascii").split(".")
    except UnicodeDecodeError as exc:
        raise WireShapeError("JWE must be ASCII compact serialization") from exc
    if len(parts) != 5:
        raise WireShapeError("JWE compact serialization needs five parts")
    protected, encrypted_key, iv, ciphertext, tag = map(_unb64, parts)
    try:
        header = json.loads(protected.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WireShapeError("invalid protected JWE header") from exc
    if not isinstance(header, dict) or not all(
        isinstance(header.get(k), str) and header[k] for k in ("alg", "enc")
    ):
        raise WireShapeError("missing JWE alg or enc")
    if len(iv) < 12 or not ciphertext or len(tag) < 16:
        raise WireShapeError("incomplete JWE cryptographic fields")
    if header["alg"] == "dir" and encrypted_key:
        raise WireShapeError("direct JWE must have an empty encrypted-key part")


def validate_response(request: object, response: object) -> dict[str, Any]:
    request = validate_request(request)
    response = _object(response, "response")
    if response.get("version") != request["version"]:
        raise WireShapeError("response version differs from request")
    if response.get("hpke") not in request["hpke"]:
        raise WireShapeError("HPKE selection was not offered")
    if response.get("archive") not in request["archive"]:
        raise WireShapeError("archive selection was not offered")
    if response["archive"] != "deflate":
        raise WireShapeError("probe only supports deflate ZIP archives")
    if not isinstance(response.get("exporter"), str) or not response["exporter"]:
        raise WireShapeError("missing exporter")
    payload = _unb64(response.get("payload"))
    if len(payload) > MAX_ZIP_BYTES:
        raise WireShapeError("ZIP exceeds probe size limit")
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            if not 2 <= len(entries) <= MAX_ENTRIES:
                raise WireShapeError("unexpected ZIP entry count")
            names = [entry.filename for entry in entries]
            if len(set(names)) != len(names) or "CXP-Export/index.jwe" not in names:
                raise WireShapeError("missing index or duplicate ZIP name")
            document_names = [n for n in names if DOCUMENT_NAME.fullmatch(n)]
            if not document_names or len(document_names) != len(entries) - 1:
                raise WireShapeError("unexpected ZIP layout")
            for entry in entries:
                if entry.is_dir() or entry.file_size > MAX_ENTRY_BYTES:
                    raise WireShapeError("ZIP directory or oversized member")
                if entry.compress_type != zipfile.ZIP_DEFLATED:
                    raise WireShapeError("ZIP member is not deflated")
                _jwe_shape(archive.read(entry))
    except (zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        raise WireShapeError("invalid ZIP archive") from exc
    return {
        "request_shape": "PASS",
        "response_negotiation": "PASS",
        "zip_jwe_shape": "PASS",
        "jwe_authentication": "NOT_EVALUABLE",
        "hpke_to_jwe_binding": "NOT_EVALUABLE",
        "challenge_signature": "NOT_EVALUABLE",
        "cxf_plaintext": "NOT_EVALUABLE",
        "provider_interoperability": "NOT_EVALUABLE",
        "document_count": len(document_names),
    }


def _synthetic_jwe(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    # Genuine RFC 7516 compact JWE using direct AES-GCM solely as a shape
    # fixture. The CXP draft does not specify how to map HPKE to JWE.
    protected = _b64(b'{"alg":"dir","enc":"A128GCM"}')
    sealed = AESGCM(key).encrypt(iv, plaintext, protected.encode("ascii"))
    return f"{protected}..{_b64(iv)}.{_b64(sealed[:-16])}.{_b64(sealed[-16:])}".encode("ascii")


def synthetic_fixture() -> tuple[dict[str, Any], dict[str, Any]]:
    private = x25519.X25519PrivateKey.from_private_bytes(hashlib.sha256(b"cxp-probe-jwk").digest())
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    suite = {
        "mode": "base",
        "kem": 32,
        "kdf": 1,
        "aead": 1,
        "key": {"kty": "OKP", "crv": "X25519", "x": _b64(public)},
    }
    request = {
        "version": 0,
        "hpke": [suite],
        "archive": ["deflate"],
        "mode": "indirect",
        "importer": "importer.example.test",
        "credentialTypes": ["passkey"],
    }
    key = hashlib.sha256(b"cxp-probe-only-not-provider-key").digest()[:16]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, plaintext, iv in (
            ("CXP-Export/index.jwe", b'{"documents":["fixture"]}', b"\x01" * 12),
            ("CXP-Export/documents/fixture.jwe", b'{"synthetic":true}', b"\x02" * 12),
        ):
            info = zipfile.ZipInfo(name, date_time=(2024, 10, 3, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, _synthetic_jwe(plaintext, key, iv))
    response = {
        "version": 0,
        "hpke": suite,
        "archive": "deflate",
        "exporter": "exporter.example.test",
        "payload": _b64(buffer.getvalue()),
    }
    return request, response
