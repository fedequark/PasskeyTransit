from cryptography.hazmat.primitives.asymmetric import x25519

from passkeytransit.hpke import open_base, seal_base


def test_hpke_rfc9180_x25519_base_vector():
    recipient_private = x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
    )
    ephemeral_private = x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
    )
    info = bytes.fromhex("4f6465206f6e2061204772656369616e2055726e")
    plaintext = bytes.fromhex("4265617574792069732074727574682c20747275746820626561757479")
    aad = bytes.fromhex("436f756e742d30")
    enc, ciphertext = seal_base(
        recipient_private.public_key(), plaintext, info=info, aad=aad, ephemeral_private_key=ephemeral_private
    )
    assert enc.hex() == "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
    assert ciphertext.hex() == (
        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9"
        "6d8770ac83d07bea87e13c512a"
    )
    assert open_base(recipient_private, enc, ciphertext, info=info, aad=aad) == plaintext
