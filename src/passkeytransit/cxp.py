from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import zlib
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric import x25519

from .cxf import assert_valid_passkey_document
from .hpke import AEAD_ID, KDF_ID, KEM_ID, HpkeError, open_base, public_jwk, public_key_from_jwk, seal_base
from .model import b64url, unb64url


CXP_DRAFT_ID = "cxp-v1.0-wd-20241003"
EXPERIMENTAL_BINDING = "passkeytransit-cxp-binding-v1"
HPKE_INFO = b"PasskeyTransit CXP v0 CXF payload"


class CxpError(ValueError):
    pass


class NegotiationError(CxpError):
    pass


class ReplayDetected(CxpError):
    pass


@dataclass(frozen=True)
class ImportSession:
    request: dict[str, Any]
    private_key: x25519.X25519PrivateKey
    request_id: str
    challenge: bytes


class ReplayCache:
    """Process-local reference cache; production use requires durable atomic storage."""

    def __init__(self) -> None:
        self._used: set[str] = set()
        self._lock = threading.Lock()

    def consume(self, token: str) -> None:
        with self._lock:
            if token in self._used:
                raise ReplayDetected("CXP response has already been imported")
            self._used.add(token)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def _inflate(data: bytes) -> bytes:
    return zlib.decompress(data, wbits=-zlib.MAX_WBITS)


def _suite(key: dict[str, str]) -> dict[str, Any]:
    return {"mode": "base", "kem": KEM_ID, "kdf": KDF_ID, "aead": AEAD_ID, "key": key}


def create_import_session(
    importer: str,
    *,
    challenge: bytes | None = None,
    request_id: str | None = None,
) -> ImportSession:
    if not importer:
        raise ValueError("importer must be a non-empty RP identifier")
    private_key = x25519.X25519PrivateKey.generate()
    actual_challenge = challenge or secrets.token_bytes(32)
    actual_request_id = request_id or secrets.token_hex(16)
    if len(actual_challenge) < 16:
        raise ValueError("challenge must contain at least 16 bytes")
    request = {
        "version": 0,
        "hpke": [_suite(public_jwk(private_key.public_key()))],
        "archive": ["deflate"],
        "mode": "direct",
        "importer": importer,
        "credentialTypes": ["passkey"],
        "knownExtensions": ["fido2Extensions"],
        "_passkeyTransit": {
            "binding": EXPERIMENTAL_BINDING,
            "requestId": actual_request_id,
            "challenge": b64url(actual_challenge),
        },
    }
    return ImportSession(request, private_key, actual_request_id, actual_challenge)


def _select_request(request: object) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise NegotiationError("export request must be an object")
    if request.get("version") != 0:
        raise NegotiationError("only CXP draft version 0 is supported")
    if request.get("mode") != "direct" or not isinstance(request.get("importer"), str):
        raise NegotiationError("only direct mode with an importer is supported")
    if "deflate" not in request.get("archive", []):
        raise NegotiationError("no supported archive algorithm")
    for candidate in request.get("hpke", []):
        if not isinstance(candidate, dict):
            continue
        if (
            candidate.get("mode") == "base"
            and candidate.get("kem") == KEM_ID
            and candidate.get("kdf") == KDF_ID
            and candidate.get("aead") == AEAD_ID
        ):
            public_key_from_jwk(candidate.get("key"))
            return candidate
    raise NegotiationError("no supported HPKE parameter set")


def _binding(request: dict[str, Any]) -> dict[str, str]:
    value = request.get("_passkeyTransit")
    if not isinstance(value, dict) or value.get("binding") != EXPERIMENTAL_BINDING:
        raise NegotiationError("experimental challenge binding is required")
    request_id, challenge = value.get("requestId"), value.get("challenge")
    if not isinstance(request_id, str) or not request_id or not isinstance(challenge, str):
        raise NegotiationError("invalid experimental challenge binding")
    try:
        if len(unb64url(challenge)) < 16:
            raise ValueError
    except Exception as exc:
        raise NegotiationError("invalid challenge") from exc
    return {"requestId": request_id, "challenge": challenge}


def _aad(request: dict[str, Any], response_metadata: dict[str, Any]) -> bytes:
    return _canonical({"draft": CXP_DRAFT_ID, "request": request, "response": response_metadata})


def export_cxf(request: object, document: object, *, exporter: str) -> dict[str, Any]:
    if not exporter:
        raise ValueError("exporter must be a non-empty RP identifier")
    selected = _select_request(request)
    assert isinstance(request, dict)
    binding = _binding(request)
    assert_valid_passkey_document(document)
    metadata = {"version": 0, "hpke": selected, "archive": "deflate", "exporter": exporter}
    plaintext = _deflate(_canonical(document))
    enc, ciphertext = seal_base(
        public_key_from_jwk(selected["key"]), plaintext, info=HPKE_INFO, aad=_aad(request, metadata)
    )
    return {
        **metadata,
        "payload": b64url(ciphertext),
        "_passkeyTransit": {
            "binding": EXPERIMENTAL_BINDING,
            "requestId": binding["requestId"],
            "challengeHash": b64url(hashlib.sha256(unb64url(binding["challenge"])).digest()),
            "enc": b64url(enc),
        },
    }


def import_cxf(
    session: ImportSession,
    response: object,
    *,
    expected_exporter: str,
    replay_cache: ReplayCache,
) -> dict[str, Any]:
    if not isinstance(response, dict):
        raise CxpError("export response must be an object")
    selected = _select_request(session.request)
    request_binding = _binding(session.request)
    if request_binding["requestId"] != session.request_id or unb64url(request_binding["challenge"]) != session.challenge:
        raise CxpError("import session does not match its export request")
    if response.get("version") != session.request.get("version"):
        raise NegotiationError("CXP version downgrade or mismatch refused")
    if response.get("hpke") != selected or response.get("archive") != "deflate":
        raise NegotiationError("response parameters were not offered by importer")
    if response.get("exporter") != expected_exporter:
        raise CxpError("unexpected exporter identifier")
    binding = response.get("_passkeyTransit")
    expected_hash = b64url(hashlib.sha256(session.challenge).digest())
    if not isinstance(binding, dict) or binding.get("binding") != EXPERIMENTAL_BINDING:
        raise CxpError("missing experimental response binding")
    if binding.get("requestId") != session.request_id or not hmac.compare_digest(str(binding.get("challengeHash")), expected_hash):
        raise CxpError("response challenge binding does not match request")
    try:
        enc = unb64url(str(binding["enc"]))
        ciphertext = unb64url(str(response["payload"]))
    except Exception as exc:
        raise CxpError("invalid response byte encoding") from exc
    metadata = {name: response[name] for name in ("version", "hpke", "archive", "exporter")}
    try:
        compressed = open_base(session.private_key, enc, ciphertext, info=HPKE_INFO, aad=_aad(session.request, metadata))
        document = json.loads(_inflate(compressed).decode("utf-8"))
    except (HpkeError, zlib.error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CxpError("credential payload authentication or decoding failed") from exc
    assert_valid_passkey_document(document)
    replay_token = hashlib.sha256(session.request_id.encode("utf-8") + b"\x00" + session.challenge).hexdigest()
    replay_cache.consume(replay_token)
    return document


def run_cxp_reference(output_path: Any) -> dict[str, Any]:
    from pathlib import Path

    from .cxf import build_passkey_document
    from .model import generate_synthetic_passkey

    credential = generate_synthetic_passkey(20260912, 12)
    document = build_passkey_document(credential, timestamp=1789167600)
    session = create_import_session("importer.example.test")
    response = export_cxf(session.request, document, exporter="exporter.example.test")
    recovered = import_cxf(
        session, response, expected_exporter="exporter.example.test", replay_cache=ReplayCache()
    )
    result = {
        "phase": 4,
        "draft": CXP_DRAFT_ID,
        "profile": "experimental-single-cxf-document",
        "hpke": {"mode": "base", "kem": KEM_ID, "kdf": KDF_ID, "aead": AEAD_ID},
        "archive": "deflate",
        "round_trip_equal": recovered == document,
        "ciphertext_bytes": len(unb64url(response["payload"])),
        "normative_interoperability_claimed": False,
        "limitations": ["draft-omits-challenge-fields", "draft-omits-hpke-encapsulation-field", "zip-jwe-not-implemented"],
    }
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result
