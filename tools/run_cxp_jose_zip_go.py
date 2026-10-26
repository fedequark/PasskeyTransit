"""Exercise a CXP-shaped JOSE ZIP with jwx/v4 decrypting each JWE member."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tools")]

from passkeytransit.cxf import build_passkey_document  # noqa: E402
from passkeytransit.cxp import create_import_session  # noqa: E402
from passkeytransit.cxp_jose_zip_profile import INDEX, export_zip_jose, validate_external_decrypted  # noqa: E402
from passkeytransit.model import b64url, generate_synthetic_passkey, unb64url  # noqa: E402
from run_jose_hpke_go_interop import call_go  # noqa: E402


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def go_import(binary: Path, request: dict, response: dict, private_key: x25519.X25519PrivateKey) -> dict:
    key = private_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    archive_bytes = unb64url(response["payload"])
    if len(archive_bytes) > 1024 * 1024:
        raise ValueError("archive exceeds limit")
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        names = archive.namelist()
        if len(names) != 2 or len(set(names)) != 2 or INDEX not in names:
            raise ValueError("invalid archive member set")
        if any(not name.startswith("CXP-Export/") or ".." in name for name in names):
            raise ValueError("invalid ZIP member name")
        decrypted = {}
        for name in names:
            info = archive.getinfo(name)
            if info.compress_type != zipfile.ZIP_DEFLATED or info.file_size > 256 * 1024:
                raise ValueError("unsupported ZIP member")
            compact = archive.read(name)
            if len(compact) > 256 * 1024:
                raise ValueError("JWE member exceeds limit")
            result = call_go(binary, "decrypt", key, compact.decode("ascii"), success=True)
            decrypted[name] = unb64url(result["payload"])
    return validate_external_decrypted(request, response, decrypted, expected_exporter="exporter.example.test")


def change_index_jwe(response: dict) -> dict:
    changed = json.loads(json.dumps(response))
    source = io.BytesIO(unb64url(response["payload"]))
    target = io.BytesIO()
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in original.namelist():
            value = original.read(name)
            if name == INDEX:
                parts = value.decode("ascii").split(".")
                ciphertext = bytearray(unb64url(parts[3]))
                ciphertext[0] ^= 1
                parts[3] = b64url(bytes(ciphertext))
                value = ".".join(parts).encode("ascii")
            archive.writestr(name, value)
    changed["payload"] = b64url(target.getvalue())
    return changed


def rejected(action) -> bool:
    try:
        action()
    except (ValueError, KeyError, UnicodeError, zipfile.BadZipFile, RuntimeError):
        return True
    return False


def run(binary: Path, go: Path) -> dict:
    document = build_passkey_document(
        generate_synthetic_passkey(20261026, 4), timestamp=1793018074,
        hmac_with_uv=b"u" * 32, hmac_without_uv=b"n" * 32,
    )
    session = create_import_session("importer.example.test")
    response = export_zip_jose(session.request, document, exporter="exporter.example.test")
    recovered = go_import(binary, session.request, response, session.private_key)
    wrong = x25519.X25519PrivateKey.generate()
    changed_exporter = json.loads(json.dumps(response))
    changed_exporter["exporter"] = "impostor.example.test"
    changed_archive = json.loads(json.dumps(response))
    changed_archive["archive"] = "store"
    checks = {
        "jose_zip_synthetic_cxf_recovered_with_external_go_crypto": recovered == document,
        "modified_index_jwe_rejected": rejected(lambda: go_import(binary, session.request, change_index_jwe(response), session.private_key)),
        "wrong_recipient_rejected": rejected(lambda: go_import(binary, session.request, response, wrong)),
        "altered_exporter_rejected": rejected(lambda: go_import(binary, session.request, changed_exporter, session.private_key)),
        "unoffered_archive_rejected": rejected(lambda: go_import(binary, session.request, changed_archive, session.private_key)),
    }
    if not all(checks.values()):
        raise ValueError(f"CXP-shaped JOSE ZIP checks failed: {checks}")
    return {
        "evidence_class": "project-cxp-zip-using-external-jose-library-cryptography",
        "profile": "passkeytransit-cxp-jose-hpke-zip-v1",
        "go_library": "github.com/lestrrat-go/jwx/v4@v4.6.0",
        "go_version": subprocess.check_output([str(go), "version"], text=True).strip(),
        "document_sha256": sha(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()),
        "source_sha256": {
            "profile": sha((ROOT / "src/passkeytransit/cxp_jose_zip_profile.py").read_bytes()),
            "jose": sha((ROOT / "src/passkeytransit/jose_hpke_ke.py").read_bytes()),
            "go_adapter": sha((ROOT / "interop/jose_hpke_go/main.go").read_bytes()),
            "go_mod": sha((ROOT / "interop/jose_hpke_go/go.mod").read_bytes()),
            "go_sum": sha((ROOT / "interop/jose_hpke_go/go.sum").read_bytes()),
            "runner": sha(Path(__file__).read_bytes()),
        },
        "checks": checks,
        "all_checks_pass": True,
        "limitations": [
            "CXP ZIP/index/transport binding is project-authored and not specified by JOSE draft -22",
            "Go library decrypts JWE members but does not import a passkey into a credential provider",
            "synthetic CXF content only; no RP assertion, PRF evaluation, or provider identity authentication",
            "no durable replay cache or platform transfer flow",
        ],
    }


if __name__ == "__main__":
    binary = Path(sys.argv[1])
    go = Path(sys.argv[2])
    output = Path(sys.argv[3]) if len(sys.argv) > 3 else ROOT / "experiments/cxp_jose_zip_go/report.json"
    result = run(binary, go)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
