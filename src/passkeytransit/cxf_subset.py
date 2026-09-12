from __future__ import annotations

from .model import SyntheticPasskey, b64url, unb64url


SUBSET_NOTICE = (
    "Experimental internal representation; not a complete CXF 1.0 conformance claim"
)


def export_subset(credential: SyntheticPasskey) -> dict[str, object]:
    extensions: dict[str, str] = {}
    if credential.prf_secret is not None:
        extensions["prfSecretControl"] = b64url(credential.prf_secret)
    if credential.large_blob is not None:
        extensions["largeBlob"] = b64url(credential.large_blob)
    return {
        "_notice": SUBSET_NOTICE,
        "type": "passkey",
        "credentialId": b64url(credential.credential_id),
        "rpId": credential.rp_id,
        "userHandle": b64url(credential.user_handle),
        "username": credential.username,
        "userDisplayName": credential.user_display_name,
        "privateKeyPkcs8": b64url(credential.private_key_pkcs8),
        "extensions": extensions,
    }


def import_subset(document: dict[str, object]) -> SyntheticPasskey:
    if document.get("type") != "passkey":
        raise ValueError("unsupported credential type")
    extensions = document.get("extensions", {})
    if not isinstance(extensions, dict):
        raise ValueError("extensions must be an object")
    return SyntheticPasskey(
        credential_id=unb64url(str(document["credentialId"])),
        rp_id=str(document["rpId"]),
        user_handle=unb64url(str(document["userHandle"])),
        username=str(document["username"]),
        user_display_name=str(document["userDisplayName"]),
        private_key_pkcs8=unb64url(str(document["privateKeyPkcs8"])),
        prf_secret=(
            unb64url(str(extensions["prfSecretControl"]))
            if "prfSecretControl" in extensions
            else None
        ),
        large_blob=(
            unb64url(str(extensions["largeBlob"]))
            if "largeBlob" in extensions
            else None
        ),
    )

