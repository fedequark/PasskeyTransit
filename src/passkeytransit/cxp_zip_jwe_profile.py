"""Experimental HPKE-wrapped JWE files in a CXP-shaped ZIP archive.

The 2024 CXP draft does not define an HPKE-to-JWE key-management mapping.
This private JOSE algorithm is a test profile, not CXP conformance.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import secrets
import zipfile
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .cxf import assert_valid_passkey_document
from .cxp import CxpError, ImportSession, ReplayCache, ReplayDetected, _aad, _binding, _canonical, _select_request
from .cxp_wire_probe import WireShapeError, _b64, _unb64, validate_response
from .hpke import HpkeError, open_base, public_key_from_jwk, seal_base
from .model import b64url, unb64url

PROFILE = "passkeytransit-cxp-zip-jwe-v1"
JOSE_ALG = "urn:passkeytransit:hpke-wrap-v1"
HPKE_INFO = b"PasskeyTransit experimental CXP ZIP/JWE CEK v1"
INDEX = "CXP-Export/index.jwe"


class ZipJweError(CxpError):
    pass


def _metadata(response: dict[str, Any]) -> dict[str, Any]:
    return {key: response[key] for key in ("version", "hpke", "archive", "exporter")}


def _seal_member(
    name: str, plaintext: bytes, request: dict[str, Any], metadata: dict[str, Any]
) -> bytes:
    header = {
        "alg": JOSE_ALG,
        "enc": "A128GCM",
        "cty": "application/cxf+json" if name != INDEX else "application/json",
        "profile": PROFILE,
        "name": name,
    }
    protected = _b64(_canonical(header))
    cek = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)
    aad = protected.encode("ascii") + b"\x00" + hashlib.sha256(_aad(request, metadata)).digest()
    recipient = public_key_from_jwk(metadata["hpke"]["key"])
    enc, wrapped = seal_base(recipient, cek, info=HPKE_INFO, aad=aad)
    sealed = AESGCM(cek).encrypt(iv, plaintext, protected.encode("ascii"))
    return f"{protected}.{_b64(enc + wrapped)}.{_b64(iv)}.{_b64(sealed[:-16])}.{_b64(sealed[-16:])}".encode("ascii")


def _open_member(
    name: str, compact: bytes, session: ImportSession, metadata: dict[str, Any]
) -> bytes:
    try:
        parts = compact.decode("ascii").split(".")
        if len(parts) != 5:
            raise ZipJweError("JWE compact member must have five segments")
        protected, encrypted_key, iv, ciphertext, tag = parts
        header = json.loads(_unb64(protected))
        expected = {
            "alg": JOSE_ALG,
            "enc": "A128GCM",
            "cty": "application/cxf+json" if name != INDEX else "application/json",
            "profile": PROFILE,
            "name": name,
        }
        if header != expected:
            raise ZipJweError("JWE protected header or member name differs")
        wrapped = _unb64(encrypted_key)
        nonce, payload, auth_tag = _unb64(iv), _unb64(ciphertext), _unb64(tag)
        if len(wrapped) != 64 or len(nonce) != 12 or len(auth_tag) != 16 or not payload:
            raise ZipJweError("invalid JWE cryptographic field length")
        aad = protected.encode("ascii") + b"\x00" + hashlib.sha256(_aad(session.request, metadata)).digest()
        cek = open_base(session.private_key, wrapped[:32], wrapped[32:], info=HPKE_INFO, aad=aad)
        if len(cek) != 16:
            raise ZipJweError("invalid unwrapped CEK")
        return AESGCM(cek).decrypt(nonce, payload + auth_tag, protected.encode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError, WireShapeError, HpkeError, InvalidTag) as exc:
        raise ZipJweError("JWE/HPKE authentication or decoding failed") from exc


def export_zip_jwe(request: dict[str, Any], document: dict[str, Any], *, exporter: str) -> dict[str, Any]:
    if not exporter:
        raise ZipJweError("exporter is required")
    suite = _select_request(request)
    binding = _binding(request)
    assert_valid_passkey_document(document)
    metadata = {"version": 0, "hpke": suite, "archive": "deflate", "exporter": exporter}
    identifier = secrets.token_urlsafe(12)
    document_name = f"CXP-Export/documents/{identifier}.jwe"
    index = _canonical({"documents": [identifier]})
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        for name, plaintext in ((INDEX, index), (document_name, _canonical(document))):
            member = zipfile.ZipInfo(name, date_time=(2024, 10, 3, 0, 0, 0))
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, _seal_member(name, plaintext, request, metadata))
    return {
        **metadata,
        "payload": _b64(data.getvalue()),
        "_passkeyTransit": {
            "profile": PROFILE,
            "requestId": binding["requestId"],
            "challengeHash": b64url(hashlib.sha256(unb64url(binding["challenge"])).digest()),
        },
    }


def import_zip_jwe(
    session: ImportSession, response: dict[str, Any], *, expected_exporter: str, replay_cache: ReplayCache
) -> dict[str, Any]:
    if not isinstance(response, dict):
        raise ZipJweError("response must be an object")
    try:
        validate_response(session.request, response)
        if response["exporter"] != expected_exporter:
            raise ZipJweError("unexpected exporter")
        binding = response.get("_passkeyTransit")
        expected_hash = b64url(hashlib.sha256(session.challenge).digest())
        if (
            not isinstance(binding, dict)
            or binding.get("profile") != PROFILE
            or binding.get("requestId") != session.request_id
            or not hmac.compare_digest(str(binding.get("challengeHash")), expected_hash)
        ):
            raise ZipJweError("experimental request binding mismatch")
        metadata = _metadata(response)
        with zipfile.ZipFile(io.BytesIO(_unb64(response["payload"]))) as archive:
            names = set(archive.namelist())
            index = json.loads(_open_member(INDEX, archive.read(INDEX), session, metadata))
            ids = index.get("documents") if isinstance(index, dict) else None
            if not isinstance(ids, list) or len(ids) != 1 or not isinstance(ids[0], str):
                raise ZipJweError("experimental index must name one document")
            name = f"CXP-Export/documents/{ids[0]}.jwe"
            if names != {INDEX, name}:
                raise ZipJweError("index and ZIP member names differ")
            document = json.loads(_open_member(name, archive.read(name), session, metadata))
        assert_valid_passkey_document(document)
        token = hashlib.sha256(session.request_id.encode() + b"\x00" + session.challenge).hexdigest()
        replay_cache.consume(token)
        return document
    except (WireShapeError, KeyError, ValueError, zipfile.BadZipFile) as exc:
        if isinstance(exc, (ZipJweError, ReplayDetected)):
            raise
        raise ZipJweError("ZIP/JWE import failed") from exc
