"""Trace one retained Android CXF failure to the pinned AndroidX availability gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path


VERSION = "1.0.0-beta01"
BASE = "https://dl.google.com/dl/android/maven2/androidx/credentials/providerevents"
ARTIFACTS = {
    "providerevents": "faacda19efec00eff12c2658b2a955d40920a596a82e9d5f2676986b6e8fce09",
    "providerevents-play-services": "59589da41ca1402c1fcb341a33b0f7d6e566b82db71c456a78d82a350a608ec9",
}
DEFAULT_REPORT = Path(
    "experiments/android_cxf_open_pair_onboard_probe/run_40764213008/emulator-report.json"
)


def source(jar: Path, member: str, expected_hash: str) -> str:
    digest = hashlib.sha256(jar.read_bytes()).hexdigest()
    if digest != expected_hash:
        raise ValueError(f"source JAR hash mismatch: {jar} ({digest})")
    with zipfile.ZipFile(jar) as archive:
        return archive.read(member).decode("utf-8")


def verify(report: Path, source_dir: Path) -> dict:
    manager = source(
        source_dir / f"providerevents-{VERSION}-sources.jar",
        "androidx/credentials/providerevents/ProviderEventsManagerImpl.kt",
        ARTIFACTS["providerevents"],
    )
    factory = source(
        source_dir / f"providerevents-{VERSION}-sources.jar",
        "androidx/credentials/providerevents/internal/ProviderFactory.kt",
        ARTIFACTS["providerevents"],
    )
    play = source(
        source_dir / f"providerevents-play-services-{VERSION}-sources.jar",
        "androidx/credentials/providerevents/playservices/ProviderEventsApiProviderPlayServices.kt",
        ARTIFACTS["providerevents-play-services"],
    )
    for content, needle in (
        (manager, "registerCredentials: no provider dependencies found"),
        (manager, "ProviderEventsApiProviderFactory().getBestAvailableProvider(context)"),
        (factory, "if (p.isAvailable())"),
        (play, "return isAvailableOnDevice(MIN_GMS_APK_VERSION)"),
        (play, "googleApiAvailability.isGooglePlayServicesAvailable("),
        (play, "return resultCode == ConnectionResult.SUCCESS"),
    ):
        if needle not in content:
            raise ValueError(f"AndroidX source path changed: {needle}")
    match = re.search(r"const val MIN_GMS_APK_VERSION = (\d+)", play)
    if not match:
        raise ValueError("AndroidX minimum GMS version not found")
    minimum = int(match.group(1))

    observed = json.loads(report.read_text(encoding="utf-8"))
    version = observed["google_play_services_version_code"]
    if observed["android_api"] != 35 or observed["google_play_services_version_name"] != "24.23.35":
        raise ValueError("retained emulator identity changed")
    if observed["status"] != "OPEN_PAIR_INSTALL_LAUNCH_PASS" or not version < minimum:
        raise ValueError("retained emulator does not satisfy the below-minimum control")
    return {
        "status": "GMS_BELOW_ANDROIDX_PROVIDER_EVENTS_MINIMUM",
        "scope": "Availability gate for the Play-services provider in AndroidX 1.0.0-beta01 on CI run 40764213008; not a CXF transfer or a diagnosis of earlier runs without GMS version evidence.",
        "android_ci_run": 40764213008,
        "android_build_fingerprint": observed["android_build_fingerprint"],
        "observed_gms_version_name": observed["google_play_services_version_name"],
        "observed_gms_version_code": version,
        "androidx_minimum_gms_version_code": minimum,
        "source_jars": {
            name: {
                "url": f"{BASE}/{name}/{VERSION}/{name}-{VERSION}-sources.jar",
                "sha256": digest,
            }
            for name, digest in sorted(ARTIFACTS.items())
        },
        "inference": "The Play-services provider reports unavailable below its minimum; AndroidX can then emit the observed no-provider-dependencies message. This sufficient gate does not prove APK packaging is correct or rule out other failures on newer devices.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--source-dir", type=Path, default=Path("tmp"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify(args.report, args.source_dir)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
