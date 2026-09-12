from __future__ import annotations

import copy
import hashlib

import pytest

from passkeytransit.cxf import (
    build_passkey_document,
    extract_first_passkey,
    inflate_large_blob,
    private_key_matches,
    validate_passkey_document,
)
from passkeytransit.model import b64url, generate_synthetic_passkey


def sample(index: int = 6):
    source = generate_synthetic_passkey(20260912, index)
    return source, build_passkey_document(
        source,
        timestamp=1789167600,
        hmac_with_uv=hashlib.sha256(b"with-uv").digest(),
        hmac_without_uv=hashlib.sha256(b"without-uv").digest(),
        cred_blob=b"credential-blob",
        payments=False,
    )


def errors(document):
    return [finding for finding in validate_passkey_document(document) if finding.severity == "error"]


def test_cxf_document_uses_normative_envelope():
    _, document = sample()
    assert set(document) == {"version", "exporterRpId", "exporterDisplayName", "timestamp", "accounts"}
    account = document["accounts"][0]
    assert set(account) == {"id", "username", "email", "collections", "items"}
    assert account["collections"] == []
    assert not errors(document)


def test_cxf_profile_round_trip_preserves_known_values():
    source, document = sample()
    passkey = extract_first_passkey(document)
    assert passkey["credentialId"] == b64url(source.credential_id)
    assert passkey["rpId"] == source.rp_id
    assert passkey["userHandle"] == b64url(source.user_handle)
    assert passkey["fido2Extensions"]["credBlob"] == b64url(b"credential-blob")


def test_cxf_validator_rejects_invalid_base64url():
    _, document = sample()
    document["accounts"][0]["items"][0]["credentials"][0]["credentialId"] = "+/not-url-safe"
    assert any(f.requirement_id == "CXF-ENC-002" for f in errors(document))


def test_cxf_import_ignores_unknown_optional_member():
    _, document = sample()
    source = document["accounts"][0]["items"][0]["credentials"][0]
    source["futureOptionalMember"] = {"securityCritical": True}
    imported = extract_first_passkey(document)
    assert "futureOptionalMember" not in imported


def test_cxf_validator_rejects_empty_optional_array():
    _, document = sample()
    document["accounts"][0]["extensions"] = []
    assert any(f.requirement_id == "CXF-ARR-002" for f in errors(document))


def test_cxf_validator_reports_missing_required_member():
    _, document = sample()
    del document["exporterDisplayName"]
    assert any(f.requirement_id == "CXF-HDR-001" for f in errors(document))


def test_cxf_validator_rejects_unknown_major_version():
    _, document = sample()
    document["version"]["major"] = 2
    assert any(f.requirement_id == "CXF-VER-001" for f in errors(document))


def test_cxf_validator_rejects_oversized_entity_id():
    _, document = sample()
    document["accounts"][0]["id"] = b64url(b"a" * 65)
    assert any(f.requirement_id == "CXF-ACC-001" for f in errors(document))


def test_cxf_validator_rejects_wrong_credential_type():
    _, document = sample()
    document["accounts"][0]["items"][0]["credentials"][0]["type"] = "future-passkey"
    assert any(f.requirement_id == "CXF-PK-001" for f in errors(document))


def test_cxf_validator_rejects_scope_for_passkey_only_item():
    _, document = sample()
    document["accounts"][0]["items"][0]["scope"] = {"urls": [], "androidApps": []}
    assert any(f.requirement_id == "CXF-PK-002" for f in errors(document))


def test_cxf_validator_rejects_malformed_pkcs8():
    _, document = sample()
    document["accounts"][0]["items"][0]["credentials"][0]["key"] = b64url(b"not-a-key")
    assert any(f.requirement_id == "CXF-PK-006" for f in errors(document))


def test_cxf_key_matches_registered_public_key():
    source, document = sample()
    assert private_key_matches(extract_first_passkey(document), source.public_key_spki)


def test_cxf_export_rejects_nonzero_signature_counter():
    source = generate_synthetic_passkey(20260912, 0)
    with pytest.raises(ValueError, match="CXF-PK-008"):
        build_passkey_document(source, timestamp=1789167600, sign_count=1)


def test_cxf_hmac_credentials_use_normative_shape():
    _, document = sample()
    hmac_credentials = extract_first_passkey(document)["fido2Extensions"]["hmacCredentials"]
    assert set(hmac_credentials) == {"algorithm", "credWithUV", "credWithoutUV"}
    assert hmac_credentials["algorithm"] == "hmac-sha256"


def test_cxf_validator_warns_on_nonrecommended_hmac_length():
    _, document = sample()
    hmac_credentials = document["accounts"][0]["items"][0]["credentials"][0]["fido2Extensions"]["hmacCredentials"]
    hmac_credentials["credWithUV"] = b64url(b"short")
    findings = validate_passkey_document(document)
    assert any(f.requirement_id == "CXF-HMAC-004" and f.severity == "warning" for f in findings)


def test_cxf_import_ignores_unknown_hmac_algorithm():
    _, document = sample()
    hmac_credentials = document["accounts"][0]["items"][0]["credentials"][0]["fido2Extensions"]["hmacCredentials"]
    hmac_credentials["algorithm"] = "future-kdf"
    imported = extract_first_passkey(document)
    assert "hmacCredentials" not in imported["fido2Extensions"]


def test_cxf_large_blob_is_deflate_compressed_and_round_trips():
    source, document = sample()
    assert inflate_large_blob(extract_first_passkey(document)) == source.large_blob


def test_cxf_validator_rejects_nonboolean_payments():
    _, document = sample()
    document["accounts"][0]["items"][0]["credentials"][0]["fido2Extensions"]["payments"] = "false"
    assert any(f.requirement_id == "CXF-OPT-002" for f in errors(document))

