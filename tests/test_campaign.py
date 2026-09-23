from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from passkeytransit.campaign import (
    StrictPreservationError,
    _apply_profile,
    _bootstrap,
    _canonical,
    _oracle,
    build_c1_corpus,
    run_c1_reference_control,
)


PROJECT_ROOT = Path(__file__).parents[1]
PROTOCOL_PATH = PROJECT_ROOT / "experiments" / "protocol_v1.2.json"


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
    assert summary["oracle_statuses"]["webauthn_assertion"] == {"NOT_EVALUABLE": 5120, "NOT_APPLICABLE": 1024}
    assert summary["execution_statuses"]["REJECTED"] == 1024
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


def test_oracle_evidence_is_resolvable_and_hash_bound():
    oracle = _oracle("PASS", {"check": True, "values": [1, 2]})
    assert oracle["evidence_ref"] == "sha256:" + __import__("hashlib").sha256(_canonical(oracle["evidence"])).hexdigest()


def test_cluster_bootstrap_is_independent_of_input_order():
    rows = [
        {"credential_id_hash": credential, "value": value}
        for credential, value in (("z", True), ("a", False), ("m", True))
        for _ in range(2)
    ]
    forward = _bootstrap(rows, lambda row: row["value"], lambda row: True, 42)
    reverse = _bootstrap(list(reversed(rows)), lambda row: row["value"], lambda row: True, 42)
    assert forward == reverse


def test_strict_profile_rejects_required_loss():
    protocol = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
    source = next(document for _, stratum, document in build_c1_corpus(protocol) if stratum == "F1")
    lossy, declared = _apply_profile(source, "compatible-lossy")
    assert "prf_uv" in declared
    with pytest.raises(StrictPreservationError, match="prf_uv"):
        _apply_profile(lossy, "strict", source_document=source, required_properties={"prf_uv"})
