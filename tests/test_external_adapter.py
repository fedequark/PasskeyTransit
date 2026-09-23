from __future__ import annotations

import json
import sys
from pathlib import Path

from passkeytransit.campaign import build_c1_corpus
from passkeytransit.external_adapter import AdapterIdentity, run_external_adapter


def test_external_adapter_protocol_round_trip(tmp_path):
    helper = tmp_path / "adapter.py"
    helper.write_text(
        "import json,sys\n"
        "r=json.load(sys.stdin)\n"
        "json.dump({'adapter_protocol_version':1,'status':'PASS','document':r['document']},sys.stdout)\n",
        encoding="utf-8",
    )
    protocol = json.loads(Path("experiments/protocol_v1.3.json").read_text(encoding="utf-8"))
    document = build_c1_corpus(protocol)[0][2]
    result = run_external_adapter(
        [sys.executable, str(helper)],
        document,
        AdapterIdentity("fixture", "1", "local", "test"),
    )
    assert result["semantic_json_equal"] is True
    assert result["source_sha256"] == result["round_trip_sha256"]
