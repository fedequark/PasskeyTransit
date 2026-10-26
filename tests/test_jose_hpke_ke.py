"""Focused controls for the JOSE draft -22 HPKE-3-KE subset."""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import x25519

from passkeytransit.jose_hpke_ke import JoseHpkeError, open_compact, seal_compact
from passkeytransit.model import b64url, unb64url


def test_compact_roundtrip_and_header_binding() -> None:
    key = x25519.X25519PrivateKey.generate()
    compact = seal_compact(key.public_key(), b"synthetic CXF")
    assert open_compact(key, compact) == b"synthetic CXF"
    parts = compact.split(".")
    header = json.loads(unb64url(parts[0]))
    assert header["alg"] == "HPKE-3-KE"
    assert header["enc"] == "A128GCM"
    assert len(unb64url(header["ek"])) == 32
    header["enc"] = "A256GCM"
    parts[0] = b64url(json.dumps(header).encode())
    with pytest.raises(JoseHpkeError):
        open_compact(key, ".".join(parts))


def test_wrong_recipient_and_modified_ciphertext_rejected() -> None:
    key = x25519.X25519PrivateKey.generate()
    compact = seal_compact(key.public_key(), b"synthetic CXF")
    with pytest.raises(JoseHpkeError):
        open_compact(x25519.X25519PrivateKey.generate(), compact)
    parts = compact.split(".")
    payload = bytearray(unb64url(parts[3]))
    payload[0] ^= 1
    parts[3] = b64url(bytes(payload))
    with pytest.raises(JoseHpkeError):
        open_compact(key, ".".join(parts))
