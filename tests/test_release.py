from __future__ import annotations

import hashlib
import json
import zipfile

from passkeytransit.release import privacy_audit, verify_release


def test_privacy_audit_rejects_private_key_field(tmp_path):
    path = tmp_path / "raw.jsonl"
    path.write_text('{"private_key":"do-not-publish"}\n', encoding="utf-8")
    result = privacy_audit([path])
    assert result["passed"] is False


def test_privacy_audit_accepts_pretty_printed_json(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"source": {"commit": "abc"}}, indent=2), encoding="utf-8")
    result = privacy_audit([path])
    assert result["passed"] is True
    assert result["json_records_inspected"] == 1


def test_verify_release_checks_internal_and_external_hashes(tmp_path):
    archive_path = tmp_path / "release.zip"
    payload = b"evidence"
    digest = hashlib.sha256(payload).hexdigest()
    analysis = json.dumps({"input_hashes": {"test": digest}, "output_hashes": {"test": digest}}).encode()
    internal = {"entries": {
        "evidence/result.txt": digest,
        "evidence/paper/analysis_manifest.json": hashlib.sha256(analysis).hexdigest(),
    }}
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("evidence/result.txt", payload)
        archive.writestr("evidence/paper/analysis_manifest.json", analysis)
        archive.writestr("MANIFEST.json", json.dumps(internal))
    manifest_path = tmp_path / "release_manifest.json"
    manifest_path.write_text(
        json.dumps({"archive_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest()}),
        encoding="utf-8",
    )
    assert verify_release(archive_path, manifest_path)["verified"] is True


def test_verify_release_requires_v15_derivation_audit_without_manifest_opt_in(tmp_path):
    archive_path = tmp_path / "release.zip"
    protocol = json.dumps({"protocol_id": "passkeytransit-semantic-preservation-v1.5"}).encode()
    internal = {"entries": {
        "source/experiments/protocol_v1.5.json": hashlib.sha256(protocol).hexdigest(),
    }}
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("source/experiments/protocol_v1.5.json", protocol)
        archive.writestr("MANIFEST.json", json.dumps(internal))
    manifest_path = tmp_path / "release_manifest.json"
    manifest_path.write_text(
        json.dumps({
            "archive_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        }),
        encoding="utf-8",
    )
    result = verify_release(archive_path, manifest_path)
    assert result["verified"] is False
    assert result["derivation_audit"]["passed"] is False
    assert "derivation-audit" in result["entry_hash_mismatches"]


def test_verify_release_rejects_duplicate_and_undeclared_entries(tmp_path):
    archive_path = tmp_path / "release.zip"
    payload = b"one"
    internal = {"entries": {"evidence/result.txt": hashlib.sha256(payload).hexdigest()}}
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("evidence/result.txt", payload)
        archive.writestr("evidence/result.txt", payload)
        archive.writestr("extra.txt", b"undeclared")
        archive.writestr("MANIFEST.json", json.dumps(internal))
    manifest_path = tmp_path / "release_manifest.json"
    manifest_path.write_text(
        json.dumps({"archive_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest()}),
        encoding="utf-8",
    )
    result = verify_release(archive_path, manifest_path)
    assert result["verified"] is False
    assert "duplicate-entry:evidence/result.txt" in result["entry_hash_mismatches"]
    assert "undeclared-entry:extra.txt" in result["entry_hash_mismatches"]
