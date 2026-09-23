from __future__ import annotations

import json
from pathlib import Path


class ProtocolValidationError(ValueError):
    """Raised when the frozen protocol is internally inconsistent."""


def _unique_ids(items: list[dict[str, object]], label: str) -> set[str]:
    ids = [str(item.get("id", "")) for item in items]
    if any(not value for value in ids):
        raise ProtocolValidationError(f"{label} contains an empty id")
    if len(ids) != len(set(ids)):
        raise ProtocolValidationError(f"{label} contains duplicate ids")
    return set(ids)


def validate_protocol(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ProtocolValidationError("unsupported protocol schema_version")
    protocol_id = str(data.get("protocol_id", ""))
    if not protocol_id.endswith(("v1.0", "v1.1", "v1.2", "v1.3", "v1.4", "v1.5")):
        raise ProtocolValidationError("protocol_id must identify a supported frozen protocol")

    rqs = set(map(str, data.get("research_questions", [])))
    if rqs != {"RQ1", "RQ2", "RQ3", "RQ4"}:
        raise ProtocolValidationError("protocol must define RQ1 through RQ4")

    strata = data.get("feature_strata", [])
    routes = data.get("routes", [])
    claims = data.get("claims", [])
    if not isinstance(strata, list) or not isinstance(routes, list) or not isinstance(claims, list):
        raise ProtocolValidationError("strata, routes, and claims must be lists")
    stratum_ids = _unique_ids(strata, "feature_strata")
    route_ids = _unique_ids(routes, "routes")
    _unique_ids(claims, "claims")

    providers = set(map(str, data.get("providers", [])))
    for route in routes:
        chain = list(map(str, route.get("chain", [])))
        if len(chain) < 2 or chain[0] != "reference":
            raise ProtocolValidationError(f"invalid route chain: {route.get('id')}")
        unknown = set(chain) - providers
        if unknown:
            raise ProtocolValidationError(f"route uses unknown providers: {sorted(unknown)}")

    oracles = set(map(str, data.get("oracles", [])))
    for claim in claims:
        if str(claim.get("rq")) not in rqs:
            raise ProtocolValidationError(f"claim {claim.get('id')} uses unknown RQ")
        unknown = set(map(str, claim.get("required_oracles", []))) - oracles
        if unknown:
            raise ProtocolValidationError(
                f"claim {claim.get('id')} uses unknown oracles: {sorted(unknown)}"
            )

    analysis_policy = data.get("analysis_policy", {})
    if protocol_id.endswith("v1.2"):
        behavioral = set(map(str, analysis_policy.get("false_reassurance_behavioral_oracles", [])))
        format_only = set(map(str, analysis_policy.get("format_only_oracles", [])))
        if not behavioral or behavioral - oracles:
            raise ProtocolValidationError("v1.2 must register valid behavioral false-reassurance oracles")
        if not format_only or format_only - oracles or behavioral & format_only:
            raise ProtocolValidationError("v1.2 format-only oracles must be valid and disjoint")
        if data.get("campaigns", {}).get("C1", {}).get("challenge_policy") != "fresh-32-byte-cryptographic-random-per-ceremony":
            raise ProtocolValidationError("v1.2 must require fresh random WebAuthn challenges")
    if protocol_id.endswith(("v1.3", "v1.4", "v1.5")):
        behavioral = set(map(str, analysis_policy.get("browser_executed_behavioral_oracles", [])))
        representation = set(map(str, analysis_policy.get("nonexecuted_representation_oracles", [])))
        format_only = set(map(str, analysis_policy.get("format_only_oracles", [])))
        if behavioral != {"uv", "large_blob"}:
            raise ProtocolValidationError("corrective behavioral estimand must contain only executed browser oracles")
        if not representation or representation - oracles:
            raise ProtocolValidationError("corrective protocol must register valid nonexecuted representation oracles")
        if not format_only or format_only - oracles:
            raise ProtocolValidationError("corrective protocol must register valid format-only oracles")
        if behavioral & representation or behavioral & format_only or representation & format_only:
            raise ProtocolValidationError("corrective protocol oracle capability classes must be disjoint")
        challenge_policy = data.get("campaigns", {}).get("C1", {}).get("challenge_policy")
        expected_policy = (
            "fresh-32-byte-nonce-derived-domain-separated-source-bound-challenge-plus-signed-extension-witness"
            if protocol_id.endswith("v1.5")
            else
            "fresh-32-byte-nonce-derived-domain-separated-source-bound-challenge"
            if protocol_id.endswith("v1.4")
            else "fresh-32-byte-nonce-derived-domain-separated-attempt-bound-challenge"
        )
        if challenge_policy != expected_policy:
            raise ProtocolValidationError("corrective protocol must require the registered WebAuthn challenge binding")
        if protocol_id.endswith(("v1.4", "v1.5")):
            expected_uncertainty = (
                "exact-designed-census-no-sampling-interval-design-weighted-aggregates"
                if protocol_id.endswith("v1.5")
                else "exact-designed-census-no-sampling-interval"
            )
            if analysis_policy.get("uncertainty_interpretation") != expected_uncertainty:
                raise ProtocolValidationError("corrective protocol has an invalid uncertainty interpretation")
            binding = str(data.get("campaigns", {}).get("C1", {}).get("transcript_binding", ""))
            for required in ("source-public-key", "user-handle", "rp-id", "origin"):
                if protocol_id.endswith("v1.4") and required not in binding:
                    raise ProtocolValidationError(f"v1.4 transcript binding is missing {required}")
            if protocol_id.endswith("v1.5"):
                for required in ("primary challenge", "extension observation"):
                    if required not in binding:
                        raise ProtocolValidationError(f"v1.5 transcript binding is missing {required}")
                storage_model = str(data.get("campaigns", {}).get("C3", {}).get("storage_model", ""))
                if "in-memory" not in storage_model or "not-durable" not in storage_model:
                    raise ProtocolValidationError("v1.5 must classify C3 as a non-durable in-memory simulation")

    campaigns = data.get("campaigns", {})
    if not isinstance(campaigns, dict):
        raise ProtocolValidationError("campaigns must be an object")
    c1 = campaigns.get("C1", {})
    expected_c1 = int(c1["credential_count"]) * len(c1["route_ids"])
    if expected_c1 != int(c1["attempts_per_repetition"]):
        raise ProtocolValidationError("C1 attempt count is inconsistent")
    if set(c1["route_ids"]) != route_ids:
        raise ProtocolValidationError("C1 must reference every frozen route exactly once")
    if int(c1["credential_count"]) != int(c1["credentials_per_stratum"]) * len(stratum_ids):
        raise ProtocolValidationError("C1 stratum allocation is inconsistent")

    c3 = campaigns.get("C3", {})
    expected_c3 = (
        int(c3["credential_count"])
        * len(c3["destination_profiles"])
        * len(c3["failure_points"])
    )
    if expected_c3 != int(c3["failure_sequence_count"]):
        raise ProtocolValidationError("C3 failure sequence count is inconsistent")
    if int(c3["credential_count"]) != int(c3["credentials_per_stratum"]) * len(stratum_ids):
        raise ProtocolValidationError("C3 stratum allocation is inconsistent")

    return {
        "protocol_id": data["protocol_id"],
        "research_questions": len(rqs),
        "feature_strata": len(stratum_ids),
        "routes": len(route_ids),
        "oracles": len(oracles),
        "claims": len(claims),
        "c1_attempts_per_repetition": expected_c1,
        "c3_failure_sequences": expected_c3,
        "valid": True,
    }
