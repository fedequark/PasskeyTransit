"""Gate an Android provider-events UI run on the pinned AndroidX GMS minimum."""

import argparse
import json
import re
import subprocess
from pathlib import Path


MIN_GMS_APK_VERSION = 253800000


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dumpsys", type=Path, help="Use a saved package dump for an offline replay")
    args = parser.parse_args()
    if args.dumpsys:
        dump = args.dumpsys.read_text(encoding="utf-8")
    else:
        dump = subprocess.check_output(
            ["adb", "shell", "dumpsys", "package", "com.google.android.gms"],
            text=True,
            timeout=30,
        )
    match = re.search(r"\bversionCode=(\d+)\b", dump)
    if not match:
        raise ValueError("com.google.android.gms versionCode unavailable")
    installed = int(match.group(1))
    eligible = installed >= MIN_GMS_APK_VERSION
    report = {
        "provider": "AndroidX providerevents-play-services 1.0.0-beta01",
        "minimum_gms_version_code": MIN_GMS_APK_VERSION,
        "installed_gms_version_code": installed,
        "eligible_for_provider_events_ui_probe": eligible,
        "classification": "PRECONDITION_MET" if eligible else "NOT_EVALUABLE_GMS_BELOW_MINIMUM",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    return 0 if eligible else 2


if __name__ == "__main__":
    raise SystemExit(main())
