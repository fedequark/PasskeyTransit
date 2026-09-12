from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass, replace

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True)
class SyntheticPasskey:
    credential_id: bytes
    rp_id: str
    user_handle: bytes
    username: str
    user_display_name: str
    private_key_pkcs8: bytes
    prf_secret: bytes | None
    large_blob: bytes | None

    @property
    def private_key(self) -> ec.EllipticCurvePrivateKey:
        key = serialization.load_der_private_key(self.private_key_pkcs8, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError("credential does not contain an EC private key")
        return key

    @property
    def public_key_spki(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, challenge: bytes) -> bytes:
        return self.private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))

    def prf(self, salt: bytes) -> bytes | None:
        if self.prf_secret is None:
            return None
        return hmac.new(self.prf_secret, salt, hashlib.sha256).digest()

    def evolve(self, **changes: object) -> "SyntheticPasskey":
        return replace(self, **changes)


def generate_synthetic_passkey(seed: int, index: int) -> SyntheticPasskey:
    root = hashlib.sha512(f"passkeytransit:{seed}:{index}".encode()).digest()
    scalar = (int.from_bytes(root[:32], "big") % (P256_ORDER - 1)) + 1
    private_key = ec.derive_private_key(scalar, ec.SECP256R1())
    private_der = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    digest = hashlib.sha512(root + b":identity").digest()
    return SyntheticPasskey(
        credential_id=digest[:32],
        rp_id=f"rp-{index % 5}.example.test",
        user_handle=digest[32:48],
        username=f"user-{index}@example.test",
        user_display_name=f"Synthetic User {index}",
        private_key_pkcs8=private_der,
        prf_secret=hashlib.sha256(root + b":prf").digest() if index % 2 == 0 else None,
        large_blob=(b"large-blob:" + digest) if index % 3 == 0 else None,
    )

