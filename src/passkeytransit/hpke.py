from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEM_ID = 0x0020
KDF_ID = 0x0001
AEAD_ID = 0x0001


class HpkeError(ValueError):
    """Raised when an HPKE input or ciphertext is invalid."""


def _i2osp(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or (b"\x00" * hashlib.sha256().digest_size), ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length > 255 * hashlib.sha256().digest_size:
        raise HpkeError("HKDF output length is too large")
    output = b""
    previous = b""
    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output += previous
    return output[:length]


def _labeled_extract(suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _extract(salt, b"HPKE-v1" + suite_id + label + ikm)


def _labeled_expand(suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled_info = _i2osp(length, 2) + b"HPKE-v1" + suite_id + label + info
    return _expand(prk, labeled_info, length)


def _public_bytes(key: x25519.X25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_jwk(key: x25519.X25519PublicKey) -> dict[str, str]:
    from .model import b64url

    return {"kty": "OKP", "crv": "X25519", "x": b64url(_public_bytes(key))}


def public_key_from_jwk(value: object) -> x25519.X25519PublicKey:
    from .model import unb64url

    if not isinstance(value, dict) or set(value) != {"kty", "crv", "x"}:
        raise HpkeError("HPKE key must be a public X25519 JWK")
    if value.get("kty") != "OKP" or value.get("crv") != "X25519" or not isinstance(value.get("x"), str):
        raise HpkeError("HPKE key must be a public X25519 JWK")
    try:
        raw = unb64url(value["x"])
        if len(raw) != 32:
            raise ValueError
        return x25519.X25519PublicKey.from_public_bytes(raw)
    except (TypeError, ValueError) as exc:
        raise HpkeError("invalid X25519 public key") from exc


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    suite_id = b"KEM" + _i2osp(KEM_ID, 2)
    eae_prk = _labeled_extract(suite_id, b"", b"eae_prk", dh)
    return _labeled_expand(suite_id, eae_prk, b"shared_secret", kem_context, 32)


@dataclass(frozen=True)
class _Context:
    key: bytes
    base_nonce: bytes


def _key_schedule(shared_secret: bytes, info: bytes) -> _Context:
    suite_id = b"HPKE" + _i2osp(KEM_ID, 2) + _i2osp(KDF_ID, 2) + _i2osp(AEAD_ID, 2)
    psk_id_hash = _labeled_extract(suite_id, b"", b"psk_id_hash", b"")
    info_hash = _labeled_extract(suite_id, b"", b"info_hash", info)
    key_schedule_context = b"\x00" + psk_id_hash + info_hash
    secret = _labeled_extract(suite_id, shared_secret, b"secret", b"")
    return _Context(
        key=_labeled_expand(suite_id, secret, b"key", key_schedule_context, 16),
        base_nonce=_labeled_expand(suite_id, secret, b"base_nonce", key_schedule_context, 12),
    )


def seal_base(
    recipient_public_key: x25519.X25519PublicKey,
    plaintext: bytes,
    *,
    info: bytes,
    aad: bytes,
    ephemeral_private_key: x25519.X25519PrivateKey | None = None,
) -> tuple[bytes, bytes]:
    ephemeral = ephemeral_private_key or x25519.X25519PrivateKey.generate()
    enc = _public_bytes(ephemeral.public_key())
    recipient = _public_bytes(recipient_public_key)
    shared_secret = _extract_and_expand(ephemeral.exchange(recipient_public_key), enc + recipient)
    context = _key_schedule(shared_secret, info)
    return enc, AESGCM(context.key).encrypt(context.base_nonce, plaintext, aad)


def open_base(
    recipient_private_key: x25519.X25519PrivateKey,
    enc: bytes,
    ciphertext: bytes,
    *,
    info: bytes,
    aad: bytes,
) -> bytes:
    if len(enc) != 32:
        raise HpkeError("invalid encapsulated X25519 key")
    try:
        ephemeral_public = x25519.X25519PublicKey.from_public_bytes(enc)
        recipient = _public_bytes(recipient_private_key.public_key())
        shared_secret = _extract_and_expand(recipient_private_key.exchange(ephemeral_public), enc + recipient)
        context = _key_schedule(shared_secret, info)
        return AESGCM(context.key).decrypt(context.base_nonce, ciphertext, aad)
    except (ValueError, InvalidTag) as exc:
        raise HpkeError("HPKE authentication failed") from exc
