"""The executable ZIP/JWE export must decrypt in a separate Node importer."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None, reason="Node.js unavailable")
def test_python_export_node_import_and_tamper_controls(tmp_path: Path) -> None:
    report = tmp_path / "cross_runtime.json"
    subprocess.run(
        [sys.executable, str(ROOT / "tools/run_cxp_zip_jwe_cross_runtime.py"), NODE, str(report)],
        cwd=ROOT, check=True, timeout=45,
    )
    result = json.loads(report.read_text(encoding="utf-8"))
    assert result["all_checks_pass"] is True
    assert result["checks"] == {
        "python_zip_jwe_export_node_import_equal": True,
        "node_rejects_modified_index_jwe_ciphertext": True,
        "node_rejects_modified_zip_central_crc": True,
        "node_rejects_wrong_recipient_key": True,
    }
