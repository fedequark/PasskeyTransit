from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .model import SyntheticPasskey


CHALLENGE = b"passkeytransit-baseline-challenge-v1"
PRF_SALT = b"passkeytransit-baseline-prf-salt-v1"


def evaluate(before: SyntheticPasskey, after: SyntheticPasskey) -> dict[str, bool]:
    signature = after.sign(CHALLENGE)
    try:
        before.private_key.public_key().verify(
            signature, CHALLENGE, ec.ECDSA(hashes.SHA256())
        )
        signature_valid = True
    except InvalidSignature:
        signature_valid = False

    return {
        "credential_id": before.credential_id == after.credential_id,
        "rp_id": before.rp_id == after.rp_id,
        "user_handle": before.user_handle == after.user_handle,
        "public_key": before.public_key_spki == after.public_key_spki,
        "signature": signature_valid,
        "prf": before.prf(PRF_SALT) == after.prf(PRF_SALT),
        "large_blob": before.large_blob == after.large_blob,
    }

