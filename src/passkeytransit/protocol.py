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
    if not protocol_id.endswith(("v1.0", "v1.1")):
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
