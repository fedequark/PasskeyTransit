from __future__ import annotations

import json
from pathlib import Path
from typing import Any


CAPABILITIES: list[dict[str, Any]] = [
    {
        "oracle": "webauthn_assertion",
        "status": "EXECUTED",
        "path": "Chromium virtual authenticator plus independent RP verification",
        "claim_effect": "positive and negative browser-backed observations are admissible",
    },
    {
        "oracle": "large_blob",
        "status": "EXECUTED",
        "path": "CDP credential injection followed by WebAuthn largeBlob read",
        "claim_effect": "positive and negative browser-backed observations are admissible",
    },
    {
        "oracle": "prf_uv",
        "status": "BLOCKED_BY_INTERFACE",
        "path": "native OS credential-provider test adapter or software CTAP authenticator",
        "blocker": "CDP addCredential exposes no CXF hmacCredentials seed injection",
        "claim_effect": "positive preservation remains NOT_EVALUABLE",
    },
    {
        "oracle": "prf_no_uv",
        "status": "BLOCKED_BY_INTERFACE",
        "path": "native OS credential-provider test adapter or software CTAP authenticator",
        "blocker": "CDP addCredential exposes no CXF hmacCredentials seed injection",
        "claim_effect": "positive preservation remains NOT_EVALUABLE",
    },
    {
        "oracle": "cred_blob",
        "status": "BLOCKED_BY_INTERFACE",
        "path": "native CTAP2 import path with credBlob state control",
        "blocker": "CDP addCredential exposes no credBlob injection",
        "claim_effect": "positive preservation remains NOT_EVALUABLE",
    },
    {
        "oracle": "payments_marker",
        "status": "FORMAT_ONLY",
        "path": "SPC-capable browser and enrolled payment instrument test environment",
        "blocker": "the current lab has no payment-instrument enrollment or SPC relying-party flow",
        "claim_effect": "the CXF marker is checked, but SPC behavior is NOT_EVALUABLE",
    },
    {
        "oracle": "cxp_pqc",
        "status": "OUT_OF_SCOPE",
        "path": "a separately versioned CXP-PQC profile with algorithm identifiers and transcript binding",
        "blocker": "CXP v0 does not register the exploratory hybrid construction",
        "claim_effect": "no CXP-PQC interoperability estimand is authorized",
    },
]


def write_oracle_capability_report(output_path: Path) -> dict[str, Any]:
    report = {
        "schema_version": 1,
        "evidence_rule": "only EXECUTED capabilities can support positive behavioral claims",
        "capabilities": CAPABILITIES,
        "executed_behavioral_oracles": [
            item["oracle"] for item in CAPABILITIES if item["status"] == "EXECUTED"
        ],
        "blocked_behavioral_oracles": [
            item["oracle"] for item in CAPABILITIES if item["status"] == "BLOCKED_BY_INTERFACE"
        ],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
