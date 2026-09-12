import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from passkeytransit.cxf_subset import export_subset, import_subset
from passkeytransit.experiment import run_pilot
from passkeytransit.model import generate_synthetic_passkey
from passkeytransit.oracles import evaluate
from passkeytransit.providers import migrate_route


def test_generation_is_deterministic():
    assert generate_synthetic_passkey(7, 3) == generate_synthetic_passkey(7, 3)


def test_cxf_subset_round_trip_preserves_credential():
    source = generate_synthetic_passkey(7, 4)
    assert import_subset(export_subset(source)) == source


def test_migrated_signature_verifies_with_original_public_key():
    source = generate_synthetic_passkey(7, 4)
    migrated = migrate_route(source, ["strict", "permissive", "strict"])
    challenge = b"test-challenge"
    source.private_key.public_key().verify(
        migrated.sign(challenge), challenge, ec.ECDSA(hashes.SHA256())
    )


def test_strict_route_preserves_every_oracle():
    source = generate_synthetic_passkey(7, 6)
    assert all(evaluate(source, migrate_route(source, ["strict"])).values())


def test_legacy_policy_exposes_semantic_loss():
    source = generate_synthetic_passkey(7, 6)
    result = evaluate(source, migrate_route(source, ["legacy"]))
    assert result["signature"]
    assert not result["prf"]
    assert not result["large_blob"]


def test_pilot_is_reproducible(tmp_path):
    config = {
        "schema_version": 1,
        "experiment_id": "test",
        "seed": 7,
        "credential_count": 4,
        "routes": [["strict"], ["legacy"]],
    }
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    first = run_pilot(config_path, tmp_path / "first")
    second = run_pilot(config_path, tmp_path / "second")
    assert first["manifest"]["result_sha256"] == second["manifest"]["result_sha256"]
    assert first["summary"] == second["summary"]

