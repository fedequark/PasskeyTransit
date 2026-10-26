"""ZIP/JWE controls for the project CXP-shaped JOSE draft profile."""

import io
import zipfile

import pytest

from passkeytransit.cxf import build_passkey_document
from passkeytransit.cxp import create_import_session
from passkeytransit.cxp_jose_zip_profile import INDEX, export_zip_jose, validate_external_decrypted
from passkeytransit.jose_hpke_ke import open_compact
from passkeytransit.model import generate_synthetic_passkey, unb64url


def test_two_jose_members_and_authenticated_negotiation() -> None:
    session = create_import_session("importer.example.test")
    document = build_passkey_document(generate_synthetic_passkey(20261026, 5), timestamp=1793018074)
    response = export_zip_jose(session.request, document, exporter="exporter.example.test")
    with zipfile.ZipFile(io.BytesIO(unb64url(response["payload"]))) as archive:
        assert len(archive.namelist()) == 2
        assert INDEX in archive.namelist()
        decrypted = {name: open_compact(session.private_key, archive.read(name).decode()) for name in archive.namelist()}
    assert validate_external_decrypted(
        session.request, response, decrypted, expected_exporter="exporter.example.test"
    ) == document
    changed = {**response, "exporter": "impostor.example.test"}
    with pytest.raises(ValueError):
        validate_external_decrypted(
            session.request, changed, decrypted, expected_exporter="impostor.example.test"
        )
