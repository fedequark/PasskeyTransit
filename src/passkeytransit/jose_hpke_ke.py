"""Experimental JWE HPKE-3-KE subset from draft-ietf-jose-hpke-encrypt-22.

This is a JWE cryptographic control, not a CXP provider implementation.
"""

from __future__ import annotations

import json
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .hpke import HpkeError, open_base, seal_base
from .model import b64url, unb64url

ALG = "HPKE-3-KE"
ENC = "A128GCM"
INFO = b"JOSE-HPKE rcpt\xffA128GCM\xff"


class JoseHpkeError(ValueError):
    """The JWE does not match this HPKE-3-KE subset or failed authentication."""


def _encode(value: dict[str, str]) -> str:
    return b64url(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def seal_compact(recipient: x25519.X25519PublicKey, plaintext: bytes) -> str:
    if not plaintext or len(plaintext) > 256 * 1024:
        raise JoseHpkeError("unsupported plaintext length")
    cek = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)
    ek, encrypted_key = seal_base(recipient, cek, info=INFO, aad=b"")
    protected = _encode({"alg": ALG, "enc": ENC, "ek": b64url(ek)})
    sealed = AESGCM(cek).encrypt(iv, plaintext, protected.encode("ascii"))
    return ".".join((protected, b64url(encrypted_key), b64url(iv), b64url(sealed[:-16]), b64url(sealed[-16:])))


def open_compact(recipient: x25519.X25519PrivateKey, compact: str) -> bytes:
    try:
        parts = compact.split(".")
        if len(parts) != 5:
            raise JoseHpkeError("expected compact JWE")
        protected, encrypted_key, iv, ciphertext, tag = parts
        header = json.loads(unb64url(protected))
        if not isinstance(header, dict) or set(header) != {"alg", "enc", "ek"}:
            raise JoseHpkeError("unexpected JOSE header")
        if header["alg"] != ALG or header["enc"] != ENC:
            raise JoseHpkeError("unexpected JOSE algorithm")
        ek = unb64url(header["ek"])
        wrapped = unb64url(encrypted_key)
        nonce = unb64url(iv)
        body = unb64url(ciphertext)
        auth = unb64url(tag)
        if len(ek) != 32 or len(wrapped) != 32 or len(nonce) != 12 or len(auth) != 16 or not body:
            raise JoseHpkeError("invalid JWE field length")
        cek = open_base(recipient, ek, wrapped, info=INFO, aad=b"")
        return AESGCM(cek).decrypt(nonce, body + auth, protected.encode("ascii"))
    except (ValueError, TypeError, KeyError, InvalidTag, HpkeError, json.JSONDecodeError) as exc:
        if isinstance(exc, JoseHpkeError):
            raise
        raise JoseHpkeError("JWE decoding or authentication failed") from exc
