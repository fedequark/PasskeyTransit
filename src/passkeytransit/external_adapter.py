from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .campaign import build_c1_corpus
from .cxf import assert_valid_passkey_document


ADAPTER_PROTOCOL_VERSION = 1


@dataclass(frozen=True)
class AdapterIdentity:
    name: str
    version: str
    source_url: str
    source_revision: str


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def run_external_adapter(
    command: Sequence[str], document: dict[str, Any], identity: AdapterIdentity, timeout: int = 300
) -> dict[str, Any]:
    """Execute the stable stdin/stdout CXF adapter protocol.

    The adapter receives one JSON object and must return one JSON object. This
    boundary lets the research runner identify and version an implementation
    without importing its code or treating it as a commercial provider.
    """
    request = {
        "adapter_protocol_version": ADAPTER_PROTOCOL_VERSION,
        "operation": "cxf-round-trip",
        "document": document,
    }
    completed = subprocess.run(
        list(command),
        input=json.dumps(request),
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"external adapter exited {completed.returncode}: {completed.stderr.strip()}"
        )
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("external adapter did not emit one JSON response") from exc
    if response.get("adapter_protocol_version") != ADAPTER_PROTOCOL_VERSION:
        raise ValueError("external adapter protocol version mismatch")
    if response.get("status") != "PASS" or not isinstance(response.get("document"), dict):
        raise ValueError(f"external adapter rejected the document: {response.get('error')}")
    round_tripped = response["document"]
    assert_valid_passkey_document(round_tripped)
    source_bytes = _canonical(document)
    result_bytes = _canonical(round_tripped)
    return {
        "adapter": identity.__dict__,
        "adapter_protocol_version": ADAPTER_PROTOCOL_VERSION,
        "process_exit_code": completed.returncode,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "round_trip_sha256": hashlib.sha256(result_bytes).hexdigest(),
        "semantic_json_equal": source_bytes == result_bytes,
        "adapter_metadata": response.get("metadata", {}),
    }


def run_bitwarden_interop(
    protocol_path: Path,
    cargo_path: Path,
    manifest_path: Path,
    node_path: Path,
    wasi_runner_path: Path,
    output_path: Path,
    cargo_toolchain: str | None = None,
) -> dict[str, Any]:
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    document = build_c1_corpus(protocol)[6 * 32][2]
    identity = AdapterIdentity(
        name="bitwarden/credential-exchange credential-exchange-format",
        version="0.4.0",
        source_url="https://github.com/bitwarden/credential-exchange",
        source_revision="0ee5516e4c0481ab6b0a68f8541fc39c3c3379b1",
    )
    cargo_command = [str(cargo_path)] + ([f"+{cargo_toolchain}"] if cargo_toolchain else [])
    build = subprocess.run(
        cargo_command + ["build", "--quiet", "--locked", "--target", "wasm32-wasip1", "--manifest-path", str(manifest_path)],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if build.returncode != 0:
        raise RuntimeError(f"Bitwarden adapter build failed: {build.stderr.strip()}")
    wasm_path = manifest_path.parent / "target" / "wasm32-wasip1" / "debug" / "passkeytransit-bitwarden-cxf-adapter.wasm"
    result = run_external_adapter(
        [str(node_path), str(wasi_runner_path), str(wasm_path)],
        document,
        identity,
        timeout=600,
    )
    result["evidence_class"] = "independent-open-source-parser-round-trip"
    result["limitations"] = [
        "the tested crate is a parser and serializer, not a credential-provider product flow",
        "semantic JSON equality does not establish WebAuthn import behavior or CXP interoperability",
        "the input contains deterministic synthetic key material only",
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result
