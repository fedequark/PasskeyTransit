"""A retained public transcript must fail verification after evidence tampering."""

import copy
import json
from pathlib import Path

import pytest

from tools.verify_proton_public_report import verify_report


REPORT = Path(__file__).resolve().parents[1] / "experiments/phase17_exploratory/proton_cxf_prf.json"


def load_report() -> dict:
    return json.loads(REPORT.read_text(encoding="utf-8"))


def test_pinned_proton_public_report_recomputes_signatures_and_prf_digests() -> None:
    assert verify_report(load_report()) == {
        "public_signatures_verified": 12,
        "public_prf_digests_verified": 12,
        "repetitions": 2,
    }


@pytest.mark.parametrize("field", ["signature", "prf_sha256"])
def test_proton_public_report_rejects_tampered_evidence(field: str) -> None:
    report = copy.deepcopy(load_report())
    observation = report["runs"][0]["positive"]["observations"][0]["source"]
    if field == "signature":
        original = observation["public_transcript"]["signature"]
        observation["public_transcript"]["signature"] = ("A" if original[0] != "A" else "B") + original[1:]
    else:
        observation["prf_sha256"] = "0" * 64
    with pytest.raises(AssertionError):
        verify_report(report)
