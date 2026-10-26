#!/usr/bin/env bash
set -euo pipefail

mkdir -p tmp/android-cxf-emulator-smoke
keyguard_apk=tmp/keyguard-r20261024.1.apk
monica_apk=tmp/monica-x86_64-debug.apk
expected_keyguard=58c018583b5e1d1b0e22dcdd21a9de29fde44988934a37c194cba92905b79763
observed_keyguard=$(sha256sum "$keyguard_apk" | cut -d' ' -f1)
test "$observed_keyguard" = "$expected_keyguard"
observed_monica=$(sha256sum "$monica_apk" | cut -d' ' -f1)
expected_monica=$(cut -d' ' -f1 tmp/monica-x86-apk-sha256.txt)
test "$observed_monica" = "$expected_monica"

find "$ANDROID_HOME/build-tools" -name aapt -type f | sort -V | tail -n1 > tmp/aapt-path.txt
aapt=$(cat tmp/aapt-path.txt)
test -x "$aapt"
keyguard_pkg=$("$aapt" dump badging "$keyguard_apk" | sed -n "s/^package: name='\([^']*\)'.*/\1/p")
monica_pkg=$("$aapt" dump badging "$monica_apk" | sed -n "s/^package: name='\([^']*\)'.*/\1/p")
test "$keyguard_pkg" = com.artemchep.keyguard
test "$monica_pkg" = takagi.ru.monica

adb install -r "$keyguard_apk"
adb install -r "$monica_apk"
adb shell pm path "$keyguard_pkg"
adb shell pm path "$monica_pkg"
adb shell pm path com.google.android.gms

for pkg in "$keyguard_pkg" "$monica_pkg"; do
  label=${pkg##*.}
  adb shell monkey -p "$pkg" -c android.intent.category.LAUNCHER 1 > "tmp/android-cxf-emulator-smoke/$label-monkey.txt"
  sleep 5
  adb shell pidof "$pkg" > "tmp/android-cxf-emulator-smoke/$label-pid.txt"
  adb shell uiautomator dump /sdcard/window.xml
  adb pull /sdcard/window.xml "tmp/android-cxf-emulator-smoke/$label-window.xml"
done

export KEYGUARD_PKG="$keyguard_pkg" MONICA_PKG="$monica_pkg"
export KEYGUARD_SHA256="$observed_keyguard" MONICA_SHA256="$observed_monica"
export EMULATOR_API="$(adb shell getprop ro.build.version.sdk | tr -d '\r')"
export EMULATOR_ABI="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
python3 - <<'PY'
import json
import os
from pathlib import Path

result = {
    "status": "EMULATOR_INSTALL_LAUNCH_PASS",
    "scope": "Fresh Android emulator, APK installation and foreground launch only; no credential creation, provider-events transfer, vault import, or RP assertion.",
    "android_api": int(os.environ["EMULATOR_API"]),
    "emulator_abi": os.environ["EMULATOR_ABI"],
    "google_play_services_installed": True,
    "keyguard": {
        "package": os.environ["KEYGUARD_PKG"],
        "release": "r20261024.1",
        "apk_sha256": os.environ["KEYGUARD_SHA256"],
    },
    "monica": {
        "package": os.environ["MONICA_PKG"],
        "source_commit": "5ef2f3a64b53094351210f1e316fbab51852708e",
        "apk_sha256": os.environ["MONICA_SHA256"],
    },
}
assert result["android_api"] >= 34
assert result["emulator_abi"] == "x86_64"
path = Path("tmp/android-cxf-emulator-smoke/report.json")
path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(path.read_text(encoding="utf-8"))
PY
