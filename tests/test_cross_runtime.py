from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from passkeytransit.cross_runtime import run_cross_runtime_cxp


ROOT = Path(__file__).parents[1]
NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None, reason="Node.js unavailable")
def test_cross_runtime_cxp_both_directions_and_tamper_rejection(tmp_path: Path) -> None:
    result = run_cross_runtime_cxp(
        ROOT / "experiments" / "protocol_v1.5.json",
        Path(NODE), ROOT / "interop" / "node_cxp_exchange.mjs",
        tmp_path / "cross_runtime.json",
    )
    assert result["all_checks_pass"] is True
    assert result["checks"] == {
        "node_export_python_import_equal": True,
        "python_export_node_import_equal": True,
        "node_rejects_modified_ciphertext": True,
        "software_prf_with_uv_preserved": True,
        "software_prf_without_uv_preserved": True,
        "software_prf_missing_state_rejected": True,
    }
    assert json.loads((tmp_path / "cross_runtime.json").read_text())["document_sha256"] == result["document_sha256"]
