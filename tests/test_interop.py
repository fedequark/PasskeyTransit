from pathlib import Path
import shutil

import pytest

from passkeytransit.interop import run_independent_interop


PROJECT_ROOT = Path(__file__).parents[1]


def test_independent_hpke_and_node_cxf_interoperability(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    result = run_independent_interop(
        Path(node), PROJECT_ROOT / "interop" / "node_cxf_verifier.mjs", tmp_path / "result.json"
    )
    assert result["hpke"]["native_to_reference"] is True
    assert result["hpke"]["reference_to_native"] is True
    assert result["cxf_node_consumer"]["verified"] is True
    assert result["pqc_exploration"]["round_trip"] is True
    assert result["pqc_exploration"]["cxp_normative_assessment"] == "OUT_OF_SCOPE"
    assert result["all_applicable_checks_pass"] is True
