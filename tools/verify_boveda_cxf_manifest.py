"""Check the provider-events metadata in Bóveda's pinned merged APK manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


DEFAULT_MANIFEST = Path(
    "experiments/android_cxf_open_pair_apk_manifest/run_41515980521/manifest.txt"
)
SERVICE = "androidx.credentials.providerevents.playservices.ProviderEventsMetadataHolder"
KEY = "androidx.credentials.providerevents.PROVIDER_EVENTS_API_PROVIDER_KEY"
PROVIDER = "androidx.credentials.providerevents.playservices.ProviderEventsApiProviderPlayServices"


def verify(path: Path) -> dict:
    lines = path.read_text(encoding="utf-8").splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith("      E: service ")]
    matches = []
    for start in starts:
        end = next(
            (i for i in range(start + 1, len(lines)) if lines[i].startswith("      E: ")),
            len(lines),
        )
        block = "\n".join(lines[start:end])
        if SERVICE in block:
            matches.append(block)
    if len(matches) != 1:
        raise ValueError(f"expected exactly one AndroidX metadata-holder service, got {len(matches)}")
    block = matches[0]
    for needle in (
        f'android:name(0x01010003)="{SERVICE}"',
        "android:enabled(0x0101000e)=(type 0x12)0xffffffff",
        "android:exported(0x01010010)=(type 0x12)0x0",
        "        E: meta-data ",
        f'android:name(0x01010003)="{KEY}"',
        f'android:value(0x01010024)="{PROVIDER}"',
    ):
        if needle not in block:
            raise ValueError(f"merged manifest is missing {needle}")
    if "androidx.credentials.providerevents.playservices.ImportExportFileProvider" not in "\n".join(lines):
        raise ValueError("merged manifest lacks the transfer FileProvider")
    return {
        "status": "PROVIDER_EVENTS_PLAY_SERVICES_METADATA_PRESENT",
        "scope": "Merged manifest from pinned Bóveda Local v1.11.4 x86_64 APK; does not prove runtime availability or successful transfer.",
        "github_run": 41515980521,
        "apk_sha256": "5746092a43176e6a9e92b78a5562dc8dcd016c7007a9594f1d13f76b5d1e7d7e",
        "manifest_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "metadata_holder_service": SERVICE,
        "provider_key": KEY,
        "provider_implementation": PROVIDER,
        "service_enabled": True,
        "service_exported": False,
        "transfer_file_provider_present": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify(args.manifest)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
