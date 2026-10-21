from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from run_cxp_schema_gap import analyze  # noqa: E402


def test_pinned_external_types_have_documented_draft_field_gap() -> None:
    report = analyze()
    assert report["request_fields_absent_from_upstream_types"] == ["archive", "mode"]
    assert report["response_fields_absent_from_upstream_types"] == ["archive"]
    assert report["upstream_version_storage_bits"] == 8
    assert report["draft_version_storage_bits"] == 16
