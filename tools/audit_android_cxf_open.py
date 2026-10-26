"""Compare pinned open Android CXF passkey extension paths and upstream tests.

This is a source audit plus verification of upstream CI XML, not a new Android
device or cross-provider execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEYGUARD_PIN = "ef84e290665277866adcb7f061824de06f43ef9c"
MONICA_PIN = "5ef2f3a64b53094351210f1e316fbab51852708e"
K = "common/src/commonMain/kotlin/com/artemchep/keyguard/common/service/credentialexchange/"
M = "Monica for Android/app/src/"
SOURCES = {
    "keyguard_model": ("keyguard", K + "model/CxfCredential.kt"),
    "keyguard_parser": ("keyguard", K + "impl/CxfImportServiceImpl.kt"),
    "keyguard_import": ("keyguard", K + "impl/CxfPasskeyImport.kt"),
    "keyguard_export": ("keyguard", K + "impl/CxfSecretMapper.kt"),
    "keyguard_fixture": ("keyguard", "common/src/commonTest/kotlin/com/artemchep/keyguard/common/service/credentialexchange/CxfConformanceCredentialTypesTest.kt"),
    "monica_codec": ("monica", M + "main/java/takagi/ru/monica/credentialexchange/CxfCredentialCodec.kt"),
    "monica_test": ("monica", M + "test/java/takagi/ru/monica/credentialexchange/CxfCredentialCodecTest.kt"),
}
XMLS = {
    "keyguard_conformance": ("keyguard-cxf-conformance.xml", "passkey imports every member and forces the counter to zero[desktop]"),
    "keyguard_roundtrip": ("keyguard-cxf-roundtrip.xml", "a login with a passkey and a totp round-trips[desktop]"),
    "monica_codec": ("monica-cxf-codec.xml", "prfOrOtherUnimplementedExtensionsNeverLoseTheirSeedSilently"),
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _revision(path: Path) -> str:
    return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()


def _segment(source: str, start: str, end: str) -> str:
    return source.split(start, 1)[1].split(end, 1)[0]


def run(keyguard: Path, monica: Path, upstream: Path, output: Path) -> dict:
    keyguard, monica = keyguard.resolve(), monica.resolve()
    if _revision(keyguard) != KEYGUARD_PIN or _revision(monica) != MONICA_PIN:
        raise ValueError("provider revision differs from pin")
    roots = {"keyguard": keyguard, "monica": monica}
    data = {name: (roots[provider] / path).read_bytes().replace(b"\r\n", b"\n")
            for name, (provider, path) in SOURCES.items()}
    source = {name: raw.decode("utf-8") for name, raw in data.items()}
    model = _segment(source["keyguard_model"], "data class Passkey(", ") : CxfCredential")
    if "fido2Extensions" in model or "hmacCredentials" in model:
        raise ValueError("Keyguard passkey model now includes extension state")
    if not all(field in model for field in ("credentialId:", "rpId:", "userHandle:", "key:")):
        raise ValueError("Keyguard passkey model changed")
    if "ignoreUnknownKeys = true" not in source["keyguard_parser"]:
        raise ValueError("Keyguard parser behavior changed")
    imported = _segment(source["keyguard_import"], "return DSecret.Login.Fido2Credentials(", "\n    )")
    exported = _segment(source["keyguard_export"], "return CxfCredential.Passkey(", "\n        )")
    if "fido2Extensions" in imported or "hmacCredentials" in imported or "fido2Extensions" in exported:
        raise ValueError("Keyguard mapping now contains extension state")
    if '"fido2Extensions": {"payments": true}' not in source["keyguard_fixture"]:
        raise ValueError("Keyguard conformance fixture changed")
    codec = source["monica_codec"]
    tests = source["monica_test"]
    if not all(s in codec for s in (
        'passkeyExtensionSkipReason(credential["fido2Extensions"])',
        'if (hasState("hmacCredentials")) return SkipReason.PASSKEY_PRF',
        "skip(extensionSkip)",
    )):
        raise ValueError("Monica PRF skip branch changed")
    if "prfOrOtherUnimplementedExtensionsNeverLoseTheirSeedSilently" not in tests or "SkipReason.PASSKEY_PRF" not in tests:
        raise ValueError("Monica PRF test changed")
    xml_results = {}
    for name, (filename, expected_case) in XMLS.items():
        raw = (upstream / filename).read_bytes()
        suite = ET.fromstring(raw)
        if any(int(suite.attrib[k]) for k in ("failures", "errors", "skipped")):
            raise ValueError(f"upstream suite {name} not all passing")
        cases = {case.attrib["name"] for case in suite.findall("testcase")}
        if expected_case not in cases or len(cases) != int(suite.attrib["tests"]):
            raise ValueError(f"upstream suite {name} case missing")
        xml_results[name] = {"sha256": _sha(raw), "tests": len(cases), "selected_case": expected_case}
    report = {
        "status": "SOURCE_AUDIT_WITH_UPSTREAM_TESTS_PASS",
        "source_commits": {"keyguard": KEYGUARD_PIN, "monica": MONICA_PIN},
        "source_sha256": {name: _sha(raw) for name, raw in data.items()},
        "upstream_ci": {
            "keyguard": {"run": 40229843452, "artifact_digest": "sha256:8a0224e298bbf200a1e3cada91df1d6f9fb288fec9f826c6a3018291baa1f787"},
            "monica": {"run": 40359156465, "artifact_digest": "sha256:c20587e76be94d0f42c4ab92dc3d537fb2d940f10b7efb7f681fe71b20b21098"},
        },
        "upstream_xml": xml_results,
        "observations": {
            "keyguard": "Passkey CXF model omits fido2Extensions; parser ignores unknown members and import/export mappings have no extension slot. PRF loss is inferred from source, not directly asserted by upstream tests.",
            "monica": "A non-null hmacCredentials value selects PASSKEY_PRF skip before passkey import; its upstream unit test passes.",
        },
        "limitation": "No Keyguard-to-Monica exchange or Android provider-events flow was executed; upstream tests are authored and run by their respective providers.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes((json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keyguard", type=Path, required=True)
    parser.add_argument("--monica", type=Path, required=True)
    parser.add_argument("--upstream", type=Path, default=ROOT / "experiments/android_cxf_open/upstream")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.keyguard, args.monica, args.upstream, args.output)
    print(json.dumps({"status": result["status"], "upstream_suites": len(result["upstream_xml"])}, sort_keys=True))


if __name__ == "__main__":
    main()
