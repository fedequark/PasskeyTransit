from __future__ import annotations

import copy

import pytest

from passkeytransit.cxf import build_passkey_document
from passkeytransit.cxp import (
    CxpError,
    NegotiationError,
    ReplayCache,
    ReplayDetected,
    create_import_session,
    export_cxf,
    import_cxf,
)
from passkeytransit.model import generate_synthetic_passkey


def exchange():
    document = build_passkey_document(generate_synthetic_passkey(20260912, 9), timestamp=1789167600)
    session = create_import_session("importer.example.test", challenge=b"c" * 32, request_id="request-1")
    response = export_cxf(session.request, document, exporter="exporter.example.test")
    return document, session, response


def test_cxp_round_trip_transports_valid_cxf_over_hpke():
    document, session, response = exchange()
    recovered = import_cxf(
        session, response, expected_exporter="exporter.example.test", replay_cache=ReplayCache()
    )
    assert recovered == document
    assert set(response) == {"version", "hpke", "archive", "exporter", "payload", "_passkeyTransit"}


def test_cxp_negotiates_offered_suite_and_deflate():
    _, session, response = exchange()
    assert response["hpke"] == session.request["hpke"][0]
    assert response["archive"] == "deflate"


def test_cxp_ignores_unknown_hpke_preference():
    document, session, _ = exchange()
    session.request["hpke"].insert(0, {"mode": "future", "kem": 65535, "kdf": 65535, "aead": 65535})
    response = export_cxf(session.request, document, exporter="exporter.example.test")
    assert response["hpke"] == session.request["hpke"][1]


def test_cxp_rejects_unsupported_suite():
    document, session, _ = exchange()
    session.request["hpke"][0]["aead"] = 0x0003
    with pytest.raises(NegotiationError, match="no supported HPKE"):
        export_cxf(session.request, document, exporter="exporter.example.test")


def test_cxp_rejects_unsupported_request_version():
    document, session, _ = exchange()
    session.request["version"] = 1
    with pytest.raises(NegotiationError, match="version 0"):
        export_cxf(session.request, document, exporter="exporter.example.test")


def test_cxp_rejects_version_downgrade():
    _, session, response = exchange()
    response["version"] = -1
    with pytest.raises(NegotiationError, match="version downgrade"):
        import_cxf(session, response, expected_exporter="exporter.example.test", replay_cache=ReplayCache())


def test_cxp_tampered_ciphertext_fails_authentication():
    _, session, response = exchange()
    response["payload"] = ("A" if response["payload"][0] != "A" else "B") + response["payload"][1:]
    with pytest.raises(CxpError, match="authentication or decoding"):
        import_cxf(session, response, expected_exporter="exporter.example.test", replay_cache=ReplayCache())


def test_cxp_response_is_bound_to_challenge():
    _, session, response = exchange()
    response["_passkeyTransit"]["challengeHash"] = "wrong"
    with pytest.raises(CxpError, match="challenge binding"):
        import_cxf(session, response, expected_exporter="exporter.example.test", replay_cache=ReplayCache())


def test_cxp_response_is_bound_to_exporter_metadata():
    _, session, response = exchange()
    response["exporter"] = "attacker.example.test"
    with pytest.raises(CxpError, match="unexpected exporter"):
        import_cxf(session, response, expected_exporter="exporter.example.test", replay_cache=ReplayCache())


def test_cxp_wrong_private_key_cannot_decrypt():
    _, session, response = exchange()
    other = create_import_session("importer.example.test", challenge=session.challenge, request_id=session.request_id)
    forged_session = type(session)(session.request, other.private_key, session.request_id, session.challenge)
    with pytest.raises(CxpError, match="authentication or decoding"):
        import_cxf(forged_session, response, expected_exporter="exporter.example.test", replay_cache=ReplayCache())


def test_cxp_replay_is_rejected_after_successful_import():
    _, session, response = exchange()
    cache = ReplayCache()
    import_cxf(session, response, expected_exporter="exporter.example.test", replay_cache=cache)
    with pytest.raises(ReplayDetected):
        import_cxf(session, response, expected_exporter="exporter.example.test", replay_cache=cache)


def test_cxp_rejects_invalid_cxf_before_export():
    document, session, _ = exchange()
    broken = copy.deepcopy(document)
    del broken["accounts"]
    with pytest.raises(ValueError, match="accounts"):
        export_cxf(session.request, broken, exporter="exporter.example.test")
