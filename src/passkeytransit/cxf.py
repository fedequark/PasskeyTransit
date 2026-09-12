from __future__ import annotations

import re
import zlib
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization

from .model import SyntheticPasskey, b64url, unb64url


PROFILE_ID = "cxf-passkey-profile-ps-errata-20260309"
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*={0,2}$")


@dataclass(frozen=True)
class Finding:
    requirement_id: str
    severity: str
    path: str
    message: str


class CxfValidationError(ValueError):
    def __init__(self, findings: list[Finding]):
        self.findings = findings
        super().__init__("; ".join(f"{f.path}: {f.message}" for f in findings))


def _deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def _inflate(data: bytes) -> bytes:
    return zlib.decompress(data, wbits=-zlib.MAX_WBITS)


def build_passkey_document(
    credential: SyntheticPasskey,
    *,
    timestamp: int,
    exporter_rp_id: str = "passkeytransit.example.test",
    exporter_display_name: str = "PasskeyTransit Reference Exporter",
    account_id: bytes = b"account-0",
    item_id: bytes = b"item-0",
    sign_count: int = 0,
    hmac_with_uv: bytes | None = None,
    hmac_without_uv: bytes | None = None,
    cred_blob: bytes | None = None,
    payments: bool | None = None,
) -> dict[str, Any]:
    if sign_count != 0:
        raise ValueError("CXF-PK-008: passkeys with non-zero counters must be excluded")
    if (hmac_with_uv is None) != (hmac_without_uv is None):
        raise ValueError("CXF-HMAC-002: both stable HMAC credentials are required")

    extensions: dict[str, Any] = {}
    if hmac_with_uv is not None and hmac_without_uv is not None:
        extensions["hmacCredentials"] = {
            "algorithm": "hmac-sha256",
            "credWithUV": b64url(hmac_with_uv),
            "credWithoutUV": b64url(hmac_without_uv),
        }
    if cred_blob is not None:
        extensions["credBlob"] = b64url(cred_blob)
    if credential.large_blob is not None:
        extensions["largeBlob"] = {
            "uncompressedSize": len(credential.large_blob),
            "data": b64url(_deflate(credential.large_blob)),
        }
    if payments is not None:
        extensions["payments"] = payments

    passkey: dict[str, Any] = {
        "type": "passkey",
        "credentialId": b64url(credential.credential_id),
        "rpId": credential.rp_id,
        "username": credential.username,
        "userDisplayName": credential.user_display_name,
        "userHandle": b64url(credential.user_handle),
        "key": b64url(credential.private_key_pkcs8),
    }
    if extensions:
        passkey["fido2Extensions"] = extensions

    return {
        "version": {"major": 1, "minor": 0},
        "exporterRpId": exporter_rp_id,
        "exporterDisplayName": exporter_display_name,
        "timestamp": timestamp,
        "accounts": [
            {
                "id": b64url(account_id),
                "username": "synthetic-research-account",
                "email": "synthetic@example.test",
                "collections": [],
                "items": [
                    {
                        "id": b64url(item_id),
                        "title": credential.user_display_name,
                        "credentials": [passkey],
                    }
                ],
            }
        ],
    }


def _required(obj: dict[str, Any], names: tuple[str, ...], path: str, req: str, out: list[Finding]) -> None:
    for name in names:
        if name not in obj:
            out.append(Finding(req, "error", f"{path}.{name}", "required member is missing"))


def _decode_b64(value: object, path: str, req: str, out: list[Finding]) -> bytes | None:
    if not isinstance(value, str) or not _B64URL_RE.fullmatch(value):
        out.append(Finding(req, "error", path, "must be an RFC 4648 base64url string"))
        return None
    try:
        return unb64url(value.rstrip("="))
    except Exception:
        out.append(Finding(req, "error", path, "base64url decoding failed"))
        return None


def validate_passkey_document(document: object) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(document, dict):
        return [Finding("CXF-ENC-001", "error", "$", "document must be a JSON object")]

    _required(document, ("version", "exporterRpId", "exporterDisplayName", "timestamp", "accounts"), "$", "CXF-HDR-001", findings)
    version = document.get("version")
    if isinstance(version, dict):
        _required(version, ("major", "minor"), "$.version", "CXF-HDR-001", findings)
        major, minor = version.get("major"), version.get("minor")
        if not isinstance(major, int) or isinstance(major, bool) or not 0 <= major <= 255:
            findings.append(Finding("CXF-VER-001", "error", "$.version.major", "must be an unsigned one-byte integer"))
        elif major != 1:
            findings.append(Finding("CXF-VER-001", "error", "$.version.major", "unsupported CXF major version for this profile"))
        if not isinstance(minor, int) or isinstance(minor, bool) or not 0 <= minor <= 255:
            findings.append(Finding("CXF-VER-001", "error", "$.version.minor", "must be an unsigned one-byte integer"))
        elif minor > 0:
            findings.append(Finding("CXF-FWD-001", "warning", "$.version.minor", "future minor version; known fields validated and unknown fields ignored"))
    elif version is not None:
        findings.append(Finding("CXF-HDR-001", "error", "$.version", "must be an object"))

    if not isinstance(document.get("exporterRpId"), str):
        findings.append(Finding("CXF-HDR-001", "error", "$.exporterRpId", "must be a string"))
    if not isinstance(document.get("exporterDisplayName"), str):
        findings.append(Finding("CXF-HDR-001", "error", "$.exporterDisplayName", "must be a string"))
    timestamp = document.get("timestamp")
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or not 0 <= timestamp < 2**64:
        findings.append(Finding("CXF-HDR-001", "error", "$.timestamp", "must be an unsigned eight-byte integer"))

    accounts = document.get("accounts")
    if not isinstance(accounts, list):
        findings.append(Finding("CXF-HDR-001", "error", "$.accounts", "must be an array"))
        return findings

    seen_ids: set[bytes] = set()
    for ai, account in enumerate(accounts):
        ap = f"$.accounts[{ai}]"
        if not isinstance(account, dict):
            findings.append(Finding("CXF-ACC-002", "error", ap, "must be an object"))
            continue
        _required(account, ("id", "username", "email", "collections", "items"), ap, "CXF-ACC-002", findings)
        aid = _decode_b64(account.get("id"), f"{ap}.id", "CXF-ACC-001", findings)
        if aid is not None:
            if len(aid) > 64:
                findings.append(Finding("CXF-ACC-001", "error", f"{ap}.id", "decoded identifier exceeds 64 bytes"))
            if aid in seen_ids:
                findings.append(Finding("CXF-ACC-001", "error", f"{ap}.id", "identifier is not unique"))
            seen_ids.add(aid)
        for member in ("username", "email"):
            if not isinstance(account.get(member), str):
                findings.append(Finding("CXF-ACC-002", "error", f"{ap}.{member}", "must be a string"))
        if not isinstance(account.get("collections"), list):
            findings.append(Finding("CXF-ARR-001", "error", f"{ap}.collections", "required array is missing or invalid"))
        if "extensions" in account and account.get("extensions") == []:
            findings.append(Finding("CXF-ARR-002", "error", f"{ap}.extensions", "optional empty array must be omitted"))
        items = account.get("items")
        if not isinstance(items, list):
            findings.append(Finding("CXF-ACC-002", "error", f"{ap}.items", "must be an array"))
            continue
        for ii, item in enumerate(items):
            ip = f"{ap}.items[{ii}]"
            if not isinstance(item, dict):
                findings.append(Finding("CXF-ITEM-002", "error", ip, "must be an object"))
                continue
            _required(item, ("id", "title", "credentials"), ip, "CXF-ITEM-002", findings)
            iid = _decode_b64(item.get("id"), f"{ip}.id", "CXF-ITEM-001", findings)
            if iid is not None:
                if len(iid) > 64:
                    findings.append(Finding("CXF-ITEM-001", "error", f"{ip}.id", "decoded identifier exceeds 64 bytes"))
                if iid in seen_ids:
                    findings.append(Finding("CXF-ITEM-001", "error", f"{ip}.id", "identifier is not unique"))
                seen_ids.add(iid)
            if not isinstance(item.get("title"), str):
                findings.append(Finding("CXF-ITEM-002", "error", f"{ip}.title", "must be a string"))
            for optional_array in ("tags", "extensions"):
                if optional_array in item and item.get(optional_array) == []:
                    findings.append(Finding("CXF-ARR-002", "error", f"{ip}.{optional_array}", "optional empty array must be omitted"))
            credentials = item.get("credentials")
            if not isinstance(credentials, list):
                findings.append(Finding("CXF-ITEM-002", "error", f"{ip}.credentials", "must be an array"))
                continue
            passkey_only = credentials and all(isinstance(c, dict) and c.get("type") == "passkey" for c in credentials)
            if passkey_only and "scope" in item:
                findings.append(Finding("CXF-PK-002", "error", f"{ip}.scope", "CredentialScope must not apply to passkeys"))
            for ci, credential in enumerate(credentials):
                _validate_passkey(credential, f"{ip}.credentials[{ci}]", findings)
    return findings


def _validate_passkey(value: object, path: str, findings: list[Finding]) -> None:
    if not isinstance(value, dict):
        findings.append(Finding("CXF-PK-001", "error", path, "credential must be an object"))
        return
    if value.get("type") != "passkey":
        findings.append(Finding("CXF-PK-001", "error", f"{path}.type", "profile accepts only type passkey"))
        return
    _required(value, ("credentialId", "rpId", "username", "userDisplayName", "userHandle", "key"), path, "CXF-PK-001", findings)
    _decode_b64(value.get("credentialId"), f"{path}.credentialId", "CXF-ENC-002", findings)
    handle = _decode_b64(value.get("userHandle"), f"{path}.userHandle", "CXF-ENC-002", findings)
    if handle is not None and len(handle) > 64:
        findings.append(Finding("CXF-PK-005", "error", f"{path}.userHandle", "decoded userHandle exceeds WebAuthn 64-byte limit"))
    for member in ("rpId", "username", "userDisplayName"):
        if not isinstance(value.get(member), str):
            findings.append(Finding("CXF-PK-001", "error", f"{path}.{member}", "must be a string"))
    key_bytes = _decode_b64(value.get("key"), f"{path}.key", "CXF-PK-006", findings)
    if key_bytes is not None:
        try:
            serialization.load_der_private_key(key_bytes, password=None)
        except Exception:
            findings.append(Finding("CXF-PK-006", "error", f"{path}.key", "must contain a PKCS#8 DER private key"))

    extensions = value.get("fido2Extensions")
    if extensions is None:
        return
    if not isinstance(extensions, dict):
        findings.append(Finding("CXF-PK-001", "error", f"{path}.fido2Extensions", "must be an object"))
        return
    hmac_creds = extensions.get("hmacCredentials")
    if hmac_creds is not None:
        hp = f"{path}.fido2Extensions.hmacCredentials"
        if not isinstance(hmac_creds, dict):
            findings.append(Finding("CXF-HMAC-003", "error", hp, "must be an object"))
        else:
            _required(hmac_creds, ("algorithm", "credWithUV", "credWithoutUV"), hp, "CXF-HMAC-003", findings)
            algorithm = hmac_creds.get("algorithm")
            if not isinstance(algorithm, str):
                findings.append(Finding("CXF-HMAC-003", "error", f"{hp}.algorithm", "must be a string"))
            elif algorithm != "hmac-sha256":
                findings.append(Finding("CXF-HMAC-005", "warning", f"{hp}.algorithm", "unknown algorithm entry must be ignored by importer"))
            for member in ("credWithUV", "credWithoutUV"):
                secret = _decode_b64(hmac_creds.get(member), f"{hp}.{member}", "CXF-HMAC-003", findings)
                if secret is not None and len(secret) != 32:
                    findings.append(Finding("CXF-HMAC-004", "warning", f"{hp}.{member}", "recommended decoded length is 32 bytes"))
    if "credBlob" in extensions:
        _decode_b64(extensions["credBlob"], f"{path}.fido2Extensions.credBlob", "CXF-OPT-001", findings)
    if "payments" in extensions and not isinstance(extensions["payments"], bool):
        findings.append(Finding("CXF-OPT-002", "error", f"{path}.fido2Extensions.payments", "must be boolean"))
    large_blob = extensions.get("largeBlob")
    if large_blob is not None:
        lp = f"{path}.fido2Extensions.largeBlob"
        if not isinstance(large_blob, dict):
            findings.append(Finding("CXF-LB-001", "error", lp, "must be an object"))
        else:
            _required(large_blob, ("uncompressedSize", "data"), lp, "CXF-LB-001", findings)
            size = large_blob.get("uncompressedSize")
            compressed = _decode_b64(large_blob.get("data"), f"{lp}.data", "CXF-LB-001", findings)
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                findings.append(Finding("CXF-LB-001", "error", f"{lp}.uncompressedSize", "must be an unsigned integer"))
            if compressed is not None:
                try:
                    inflated = _inflate(compressed)
                    if isinstance(size, int) and len(inflated) != size:
                        findings.append(Finding("CXF-LB-001", "error", lp, "uncompressed size does not match DEFLATE data"))
                except zlib.error:
                    findings.append(Finding("CXF-LB-001", "error", f"{lp}.data", "must contain DEFLATE-compressed bytes"))


def assert_valid_passkey_document(document: object) -> None:
    errors = [finding for finding in validate_passkey_document(document) if finding.severity == "error"]
    if errors:
        raise CxfValidationError(errors)


def extract_first_passkey(document: dict[str, Any]) -> dict[str, Any]:
    assert_valid_passkey_document(document)
    source = document["accounts"][0]["items"][0]["credentials"][0]
    known = {name: source[name] for name in ("type", "credentialId", "rpId", "username", "userDisplayName", "userHandle", "key")}
    extensions = source.get("fido2Extensions")
    if isinstance(extensions, dict):
        known_extensions: dict[str, Any] = {}
        hmac_creds = extensions.get("hmacCredentials")
        if isinstance(hmac_creds, dict) and hmac_creds.get("algorithm") == "hmac-sha256":
            known_extensions["hmacCredentials"] = {name: hmac_creds[name] for name in ("algorithm", "credWithUV", "credWithoutUV")}
        for name in ("credBlob", "largeBlob", "payments"):
            if name in extensions:
                known_extensions[name] = extensions[name]
        if known_extensions:
            known["fido2Extensions"] = known_extensions
    return known


def inflate_large_blob(passkey: dict[str, Any]) -> bytes | None:
    extensions = passkey.get("fido2Extensions", {})
    large_blob = extensions.get("largeBlob") if isinstance(extensions, dict) else None
    if not isinstance(large_blob, dict):
        return None
    data = _inflate(unb64url(str(large_blob["data"])))
    if len(data) != int(large_blob["uncompressedSize"]):
        raise CxfValidationError([Finding("CXF-LB-001", "error", "largeBlob", "size mismatch")])
    return data


def private_key_matches(passkey: dict[str, Any], expected_public_spki: bytes) -> bool:
    key = serialization.load_der_private_key(unb64url(str(passkey["key"])), password=None)
    actual = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return actual == expected_public_spki

