"""Verify the limited CXP-shaped ZIP/independent JOSE library report."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "profile": "src/passkeytransit/cxp_jose_zip_profile.py",
    "jose": "src/passkeytransit/jose_hpke_ke.py",
    "go_adapter": "interop/jose_hpke_go/main.go",
    "go_mod": "interop/jose_hpke_go/go.mod",
    "go_sum": "interop/jose_hpke_go/go.sum",
    "runner": "tools/run_cxp_jose_zip_go.py",
}
CHECKS = {
    "jose_zip_synthetic_cxf_recovered_with_external_go_crypto",
    "modified_index_jwe_rejected",
    "wrong_recipient_rejected",
    "altered_exporter_rejected",
    "unoffered_archive_rejected",
}


def verify(root: Path = ROOT) -> dict[str, object]:
    report = json.loads((root / "experiments/cxp_jose_zip_go/report.json").read_text(encoding="utf-8"))
    if report.get("evidence_class") != "project-cxp-zip-using-external-jose-library-cryptography":
        raise ValueError("wrong evidence class")
    if report.get("profile") != "passkeytransit-cxp-jose-hpke-zip-v1":
        raise ValueError("wrong experimental profile")
    if report.get("go_library") != "github.com/lestrrat-go/jwx/v4@v4.6.0":
        raise ValueError("external library changed")
    if report.get("checks") != dict.fromkeys(CHECKS, True) or report.get("all_checks_pass") is not True:
        raise ValueError("missing, failed, or unexpected control")
    if len(report.get("document_sha256", "")) != 64:
        raise ValueError("missing document digest")
    if set(report.get("source_sha256", {})) != set(SOURCES):
        raise ValueError("missing source digest")
    for name, path in SOURCES.items():
        if hashlib.sha256((root / path).read_bytes()).hexdigest() != report["source_sha256"][name]:
            raise ValueError(f"source changed: {name}")
    limitations = " ".join(report.get("limitations", []))
    if "does not import a passkey into a credential provider" not in limitations:
        raise ValueError("provider limitation missing")
    return {"status": "PASS", "controls": len(CHECKS), "scope": "project CXP ZIP with external JWE crypto only"}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2, sort_keys=True))
