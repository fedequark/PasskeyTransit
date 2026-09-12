from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from passkeytransit.campaign import build_c1_corpus, run_c1_reference_control


PROJECT_ROOT = Path(__file__).parents[1]
PROTOCOL_PATH = PROJECT_ROOT / "experiments" / "protocol_v1.0.json"


def test_c1_corpus_matches_frozen_strata():
    protocol = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
    corpus = build_c1_corpus(protocol)
    assert len(corpus) == 256
    assert Counter(stratum for _, stratum, _ in corpus) == {f"F{index}": 32 for index in range(8)}
    assert len({index for index, _, _ in corpus}) == 256


def test_phase5_c1_control_campaign_matches_registered_design(tmp_path):
    result = run_c1_reference_control(PROTOCOL_PATH, tmp_path)
    summary = result["summary"]
    assert summary["attempt_count"] == 6144
    assert summary["credential_count"] == 256
    assert summary["route_count"] == 12
    assert summary["repetitions"] == 2
    assert summary["repeat_equivalent"] is True
    assert summary["confirmatory_provider_claims_authorized"] is False
    assert sum(summary["semantic_classes"].values()) == 6144
    assert summary["oracle_statuses"]["webauthn_assertion"] == {"NOT_EVALUABLE": 6144}
    assert summary["estimands"]["false_reassurance_rate"]["denominator"] == 0
    assert len(summary["paired_route_comparisons"]) == 14
    assert all(item["paired_attempts"] == 512 for item in summary["paired_route_comparisons"])
    raw = (tmp_path / "c1_phase5_attempts.jsonl").read_text(encoding="utf-8")
    assert "privateKeyPkcs8" not in raw
    assert "synthetic@example.test" not in raw
    assert len(raw.splitlines()) == 6144
    manifest = result["manifest"]
    assert len(manifest["raw_sha256"]) == 64
    assert len(manifest["derived_sha256"]) == 64
    assert len(manifest["summary_sha256"]) == 64


def test_phase5_campaign_never_overwrites_raw_evidence(tmp_path):
    (tmp_path / "c1_phase5_attempts.jsonl").write_text("existing evidence\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="immutable"):
        run_c1_reference_control(PROTOCOL_PATH, tmp_path)
