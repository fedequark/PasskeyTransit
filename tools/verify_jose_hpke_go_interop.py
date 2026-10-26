"""Verify provenance and scope of the external JOSE HPKE crypto report."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "python_jose": "src/passkeytransit/jose_hpke_ke.py",
    "go_adapter": "interop/jose_hpke_go/main.go",
    "go_mod": "interop/jose_hpke_go/go.mod",
    "go_sum": "interop/jose_hpke_go/go.sum",
    "runner": "tools/run_jose_hpke_go_interop.py",
}
CHECKS = {
    "python_to_external_go_plaintext_equal",
    "external_go_to_python_plaintext_equal",
    "external_go_rejects_modified_ciphertext",
    "external_go_rejects_wrong_recipient",
    "python_rejects_wrong_recipient",
}


def verify(root: Path = ROOT) -> dict[str, object]:
    report = json.loads((root / "experiments/jose_hpke_go_interop/report.json").read_text(encoding="utf-8"))
    if report.get("evidence_class") != "jose-hpke-3-ke-external-library-cryptographic-interop":
        raise ValueError("unexpected evidence class")
    if report.get("jose_draft") != "draft-ietf-jose-hpke-encrypt-22":
        raise ValueError("unexpected JOSE draft")
    if report.get("go_library") != "github.com/lestrrat-go/jwx/v4@v4.6.0":
        raise ValueError("unexpected Go library revision")
    if report.get("all_checks_pass") is not True or report.get("checks") != dict.fromkeys(CHECKS, True):
        raise ValueError("missing, failed, or unexpected JOSE control")
    if len(report.get("document_sha256", "")) != 64:
        raise ValueError("missing synthetic document digest")
    if set(report.get("source_sha256", {})) != set(SOURCES):
        raise ValueError("missing source provenance")
    for name, path in SOURCES.items():
        actual = hashlib.sha256((root / path).read_bytes()).hexdigest()
        if actual != report["source_sha256"][name]:
            raise ValueError(f"source changed since JOSE run: {name}")
    if "github.com/lestrrat-go/jwx/v4 v4.6.0" not in (root / SOURCES["go_mod"]).read_text():
        raise ValueError("external library no longer pinned")
    if "no external provider passkey import" not in " ".join(report.get("limitations", [])):
        raise ValueError("provider scope missing")
    for forbidden in ("private_key", "plaintext", "jwe", "secret"):
        if forbidden in report:
            raise ValueError("sensitive field in report")
    return {"status": "PASS", "controls": len(CHECKS), "scope": "external JOSE library crypto only; no provider CXP"}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2, sort_keys=True))
