"""RFC 9180 base-mode X25519/HKDF-SHA256/ChaCha20-Poly1305 for Proton CXP."""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .hpke import HpkeError, _extract_and_expand, _i2osp, _labeled_expand, _labeled_extract, _public_bytes


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
        ephemeral = x25519.X25519PublicKey.from_public_bytes(enc)
        recipient = _public_bytes(recipient_private_key.public_key())
        shared = _extract_and_expand(recipient_private_key.exchange(ephemeral), enc + recipient)
        suite = b"HPKE" + _i2osp(0x0020, 2) + _i2osp(0x0001, 2) + _i2osp(0x0003, 2)
        psk_id_hash = _labeled_extract(suite, b"", b"psk_id_hash", b"")
        info_hash = _labeled_extract(suite, b"", b"info_hash", info)
        schedule = b"\x00" + psk_id_hash + info_hash
        secret = _labeled_extract(suite, shared, b"secret", b"")
        key = _labeled_expand(suite, secret, b"key", schedule, 32)
        nonce = _labeled_expand(suite, secret, b"base_nonce", schedule, 12)
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except (InvalidTag, ValueError) as exc:
        raise HpkeError("HPKE ciphertext authentication failed") from exc
