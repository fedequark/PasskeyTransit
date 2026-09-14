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


def test_verify_release_checks_internal_and_external_hashes(tmp_path):
    archive_path = tmp_path / "release.zip"
    payload = b"evidence"
    internal = {"entries": {"evidence/result.txt": hashlib.sha256(payload).hexdigest()}}
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("evidence/result.txt", payload)
        archive.writestr("MANIFEST.json", json.dumps(internal))
    manifest_path = tmp_path / "release_manifest.json"
    manifest_path.write_text(
        json.dumps({"archive_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest()}),
        encoding="utf-8",
    )
    assert verify_release(archive_path, manifest_path)["verified"] is True
