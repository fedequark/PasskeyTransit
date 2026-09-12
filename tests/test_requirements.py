from pathlib import Path

from passkeytransit.requirements import requirement_coverage


def test_requirement_matrix_is_internally_consistent():
    root = Path(__file__).parents[1]
    result = requirement_coverage(root / "spec" / "cxf_passkey_requirements_v1.0.json")
    assert result["valid"]
    assert result["requirement_count"] >= 25

