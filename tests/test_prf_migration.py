from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from passkeytransit.prf_migration import run_prf_migration


ROOT = Path(__file__).parents[1]
EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None or not EDGE.is_file(), reason="Node.js or Edge/Chromium unavailable")
def test_browser_prf_executed_before_and_missing_after_migration(tmp_path: Path) -> None:
    result = run_prf_migration(
        EDGE, Path(NODE), ROOT / "interop" / "node_cxp_exchange.mjs",
        tmp_path / "prf_migration.json",
    )
    assert result["all_checks_pass"] is True
    assert result["checks"]["source_prf_executed"] is True
    assert result["checks"]["same_salt_stable"] is True
    assert result["checks"]["destination_prf_result_missing"] is True
    assert result["checks"]["all_assertion_signatures_valid"] is True
