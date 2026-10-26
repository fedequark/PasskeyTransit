"""Run a synthetic, explicitly non-standard HPKE/JWE ZIP exchange."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from passkeytransit.cxf import build_passkey_document  # noqa: E402
from passkeytransit.cxp import ReplayCache, ReplayDetected, create_import_session  # noqa: E402
from passkeytransit.cxp_wire_probe import _b64, _unb64, validate_response  # noqa: E402
from passkeytransit.cxp_zip_jwe_profile import PROFILE, export_zip_jwe, import_zip_jwe  # noqa: E402
from passkeytransit.model import generate_synthetic_passkey  # noqa: E402


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def rejected(operation) -> bool:
    try:
        operation()
    except ValueError:
        return True
    return False


def altered_member(response: dict, name: str, part: int) -> dict:
    altered = copy.deepcopy(response)
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(_unb64(response["payload"]))) as source, zipfile.ZipFile(output, "w") as target:
        for member in source.infolist():
            content = source.read(member)
            if member.filename == name:
                segments = content.decode("ascii").split(".")
                value = bytearray(_unb64(segments[part]))
                value[-1] ^= 1
                segments[part] = _b64(bytes(value))
                content = ".".join(segments).encode("ascii")
            target.writestr(member, content)
    altered["payload"] = _b64(output.getvalue())
    return altered


def run() -> dict:
    document = build_passkey_document(
        generate_synthetic_passkey(20261026, 2), timestamp=1793018074,
        hmac_with_uv=b"u" * 32, hmac_without_uv=b"n" * 32,
    )
    session = create_import_session("importer.example.test")
    response = export_zip_jwe(session.request, document, exporter="exporter.example.test")
    shape = validate_response(session.request, response)
    recovered = import_zip_jwe(
        session, response, expected_exporter="exporter.example.test", replay_cache=ReplayCache()
    )
    with zipfile.ZipFile(io.BytesIO(_unb64(response["payload"]))) as archive:
        document_name = next(name for name in archive.namelist() if name.startswith("CXP-Export/documents/"))
        member_count = len(archive.namelist())

    wrong_key_session = create_import_session("importer.example.test")
    wrong_key = type(session)(session.request, wrong_key_session.private_key, session.request_id, session.challenge)
    changed_archive = copy.deepcopy(response)
    changed_archive["archive"] = "none"
    changed_exporter = copy.deepcopy(response)
    changed_exporter["exporter"] = "other.example.test"
    cache = ReplayCache()
    import_zip_jwe(session, response, expected_exporter="exporter.example.test", replay_cache=cache)
    checks = {
        "draft_zip_jwe_shape": shape["zip_jwe_shape"] == "PASS" and member_count == 2,
        "cxf_plaintext_recovered": recovered == document,
        "hmac_credentials_preserved": (
            recovered["accounts"][0]["items"][0]["credentials"][0]["fido2Extensions"]["hmacCredentials"]
            == document["accounts"][0]["items"][0]["credentials"][0]["fido2Extensions"]["hmacCredentials"]
        ),
        "modified_jwe_ciphertext_rejected": rejected(lambda: import_zip_jwe(
            session, altered_member(response, document_name, 3),
            expected_exporter="exporter.example.test", replay_cache=ReplayCache()
        )),
        "modified_hpke_wrapped_key_rejected": rejected(lambda: import_zip_jwe(
            session, altered_member(response, document_name, 1),
            expected_exporter="exporter.example.test", replay_cache=ReplayCache()
        )),
        "wrong_recipient_key_rejected": rejected(lambda: import_zip_jwe(
            wrong_key, response, expected_exporter="exporter.example.test", replay_cache=ReplayCache()
        )),
        "unoffered_archive_rejected": rejected(lambda: import_zip_jwe(
            session, changed_archive, expected_exporter="exporter.example.test", replay_cache=ReplayCache()
        )),
        "unexpected_exporter_rejected": rejected(lambda: import_zip_jwe(
            session, changed_exporter, expected_exporter="exporter.example.test", replay_cache=ReplayCache()
        )),
        "replay_rejected": rejected(lambda: import_zip_jwe(
            session, response, expected_exporter="exporter.example.test", replay_cache=cache
        )),
    }
    if not all(checks.values()):
        raise ValueError(f"experimental ZIP/JWE control failed: {checks}")
    return {
        "evidence_class": "project-authored-experimental-cxp-zip-jwe-profile",
        "profile": PROFILE,
        "source_sha256": {
            "profile": digest((ROOT / "src/passkeytransit/cxp_zip_jwe_profile.py").read_bytes()),
            "runner": digest(Path(__file__).read_bytes()),
            "hpke": digest((ROOT / "src/passkeytransit/hpke.py").read_bytes()),
        },
        "document_sha256": digest(canonical(document)),
        "archive_sha256": digest(_unb64(response["payload"])),
        "archive_member_count": member_count,
        "checks": checks,
        "all_checks_pass": True,
        "limitations": [
            "private experimental JOSE key-management algorithm, not a CXP-specified HPKE/JWE mapping",
            "project-authored exporter and importer; no external provider transfer",
            "single synthetic CXF document and in-memory replay cache",
            "challenge hash is not a provider signature or exporter authentication",
            "no browser, authenticator, or durable vault operation",
        ],
    }


if __name__ == "__main__":
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "experiments/cxp_zip_jwe_experimental/report.json"
    result = run()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
