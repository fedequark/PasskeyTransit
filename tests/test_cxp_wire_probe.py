from __future__ import annotations

import copy
import io
import zipfile

import pytest

from passkeytransit.cxp_wire_probe import (
    WireShapeError,
    _b64,
    _unb64,
    synthetic_fixture,
    validate_response,
)


def test_public_draft_envelope_shape_and_claim_boundary():
    request, response = synthetic_fixture()
    observed = validate_response(request, response)
    assert observed["document_count"] == 1
    assert observed["zip_jwe_shape"] == "PASS"
    assert observed["hpke_to_jwe_binding"] == "NOT_EVALUABLE"
    assert observed["provider_interoperability"] == "NOT_EVALUABLE"


@pytest.mark.parametrize("field,value", [
    ("version", 1),
    ("archive", "unknown"),
    ("payload", "not+base64"),
])
def test_unoffered_or_invalid_response_rejected(field, value):
    request, response = synthetic_fixture()
    response[field] = value
    with pytest.raises(WireShapeError):
        validate_response(request, response)


def test_unoffered_hpke_suite_rejected():
    request, response = synthetic_fixture()
    response["hpke"] = copy.deepcopy(response["hpke"])
    response["hpke"]["aead"] = 2
    with pytest.raises(WireShapeError, match="not offered"):
        validate_response(request, response)


@pytest.mark.parametrize("bad_name", [
    "CXP-Export/documents/../escape.jwe",
    "CXP-Export/documents/credential.json",
    "../index.jwe",
])
def test_unexpected_archive_paths_rejected(bad_name):
    request, response = synthetic_fixture()
    original = zipfile.ZipFile(io.BytesIO(_unb64(response["payload"])))
    index = original.read("CXP-Export/index.jwe")
    document = original.read("CXP-Export/documents/fixture.jwe")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("CXP-Export/index.jwe", index)
        archive.writestr(bad_name, document)
    response["payload"] = _b64(buffer.getvalue())
    with pytest.raises(WireShapeError):
        validate_response(request, response)


def test_plain_json_replaces_jwe_is_rejected():
    request, response = synthetic_fixture()
    original = zipfile.ZipFile(io.BytesIO(_unb64(response["payload"])))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("CXP-Export/index.jwe", original.read("CXP-Export/index.jwe"))
        archive.writestr("CXP-Export/documents/fixture.jwe", b'{"not":"JWE"}')
    response["payload"] = _b64(buffer.getvalue())
    with pytest.raises(WireShapeError, match="five parts"):
        validate_response(request, response)
