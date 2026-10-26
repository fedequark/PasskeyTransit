"""Positive and adversarial controls for the experimental ZIP/JWE profile."""

from __future__ import annotations

import copy
import io
import zipfile

import pytest

from passkeytransit.cxf import build_passkey_document
from passkeytransit.cxp import ReplayCache, ReplayDetected, create_import_session
from passkeytransit.cxp_wire_probe import _b64, _unb64, validate_response
from passkeytransit.cxp_zip_jwe_profile import ZipJweError, export_zip_jwe, import_zip_jwe
from passkeytransit.model import generate_synthetic_passkey


def exchange():
    document = build_passkey_document(
        generate_synthetic_passkey(20261026, 2), timestamp=1793018074,
        hmac_with_uv=b"u" * 32, hmac_without_uv=b"n" * 32,
    )
    session = create_import_session("importer.example.test", request_id="zip-jwe-1", challenge=b"c" * 32)
    response = export_zip_jwe(session.request, document, exporter="exporter.example.test")
    return document, session, response


def mutate_member(response: dict, name: str, transform) -> dict:
    altered = copy.deepcopy(response)
    source = io.BytesIO(_unb64(response["payload"]))
    output = io.BytesIO()
    with zipfile.ZipFile(source) as old, zipfile.ZipFile(output, "w") as new:
        for member in old.infolist():
            content = old.read(member)
            if member.filename == name:
                content = transform(content)
            new.writestr(member, content)
    altered["payload"] = _b64(output.getvalue())
    return altered


def test_zip_jwe_round_trip_and_structural_probe():
    document, session, response = exchange()
    shape = validate_response(session.request, response)
    assert shape["zip_jwe_shape"] == "PASS"
    assert shape["document_count"] == 1
    assert import_zip_jwe(
        session, response, expected_exporter="exporter.example.test", replay_cache=ReplayCache()
    ) == document
    assert document["accounts"][0]["items"][0]["credentials"][0]["fido2Extensions"]["hmacCredentials"]["credWithUV"].encode() not in _unb64(response["payload"])


def test_modified_jwe_ciphertext_rejected_after_zip_repacking():
    _, session, response = exchange()
    with zipfile.ZipFile(io.BytesIO(_unb64(response["payload"]))) as archive:
        document_name = next(name for name in archive.namelist() if name.startswith("CXP-Export/documents/"))

    def corrupt(compact: bytes) -> bytes:
        parts = compact.decode("ascii").split(".")
        field = parts[3]
        parts[3] = ("A" if field[0] != "A" else "B") + field[1:]
        return ".".join(parts).encode("ascii")

    altered = mutate_member(response, document_name, corrupt)
    assert validate_response(session.request, altered)["zip_jwe_shape"] == "PASS"
    with pytest.raises(ZipJweError, match="authentication"):
        import_zip_jwe(session, altered, expected_exporter="exporter.example.test", replay_cache=ReplayCache())


def test_swapped_member_name_and_wrong_key_rejected():
    _, session, response = exchange()
    other = create_import_session("importer.example.test", request_id=session.request_id, challenge=session.challenge)
    wrong_key = type(session)(session.request, other.private_key, session.request_id, session.challenge)
    with pytest.raises(ZipJweError, match="authentication"):
        import_zip_jwe(wrong_key, response, expected_exporter="exporter.example.test", replay_cache=ReplayCache())
    with zipfile.ZipFile(io.BytesIO(_unb64(response["payload"]))) as archive:
        original_name = next(name for name in archive.namelist() if name.startswith("CXP-Export/documents/"))
    altered = copy.deepcopy(response)
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(_unb64(response["payload"]))) as old, zipfile.ZipFile(output, "w") as new:
        for member in old.infolist():
            name = "CXP-Export/documents/replaced.jwe" if member.filename == original_name else member.filename
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            new.writestr(info, old.read(member))
    altered["payload"] = _b64(output.getvalue())
    with pytest.raises(ZipJweError, match="member names differ"):
        import_zip_jwe(session, altered, expected_exporter="exporter.example.test", replay_cache=ReplayCache())


def test_negotiation_change_and_replay_rejected():
    _, session, response = exchange()
    altered = copy.deepcopy(response)
    altered["archive"] = "none"
    with pytest.raises(ZipJweError):
        import_zip_jwe(session, altered, expected_exporter="exporter.example.test", replay_cache=ReplayCache())
    cache = ReplayCache()
    import_zip_jwe(session, response, expected_exporter="exporter.example.test", replay_cache=cache)
    with pytest.raises(ReplayDetected):
        import_zip_jwe(session, response, expected_exporter="exporter.example.test", replay_cache=cache)
