#!/usr/bin/env bash
set -euo pipefail

out=tmp/android-cxf-open-pair-smoke
mkdir -p "$out"
boveda_apk=tmp/boveda-v1.11.4-x86_64.apk
monica_apk=tmp/monica-x86_64-debug.apk
expected_boveda=5746092a43176e6a9e92b78a5562dc8dcd016c7007a9594f1d13f76b5d1e7d7e
expected_monica=1ad65e8d1bf2354ed09fddfd3bd084e0aa1f67da69b7f99cdf9358dfa7f2e8f8
test "$(sha256sum "$boveda_apk" | cut -d' ' -f1)" = "$expected_boveda"
test "$(sha256sum "$monica_apk" | cut -d' ' -f1)" = "$expected_monica"

aapt=$(find "$ANDROID_HOME/build-tools" -name aapt -type f | sort -V | tail -n1)
test -x "$aapt"
boveda_pkg=$("$aapt" dump badging "$boveda_apk" | sed -n "s/^package: name='\([^']*\)'.*/\1/p")
monica_pkg=$("$aapt" dump badging "$monica_apk" | sed -n "s/^package: name='\([^']*\)'.*/\1/p")
test "$boveda_pkg" = com.jlnavas3.bovedalocal
test "$monica_pkg" = takagi.ru.monica

adb shell pm path com.google.android.gms
adb install -r "$boveda_apk"
adb install -r "$monica_apk"
for entry in "boveda:$boveda_pkg" "monica:$monica_pkg"; do
  label=${entry%%:*}
  pkg=${entry#*:}
  adb shell pm path "$pkg"
  activity=.ui.MainActivity
  if [ "$label" = monica ]; then activity=.MainActivity; fi
  adb shell am start -W -n "$pkg/$activity" > "$out/$label-launch.txt"
  sleep 5
  adb shell pidof "$pkg" > "$out/$label-pid.txt"
  for attempt in 1 2 3 4 5; do
    adb shell uiautomator dump /sdcard/window.xml
    adb pull /sdcard/window.xml "$out/$label-window.xml"
    if grep -Fq "package=\"$pkg\"" "$out/$label-window.xml"; then
      printf '%s\n' "$attempt" > "$out/$label-ui-attempts.txt"
      break
    fi
    sleep 3
  done
  grep -Fq "package=\"$pkg\"" "$out/$label-window.xml"
  adb shell screencap -p /sdcard/window.png
  adb pull /sdcard/window.png "$out/$label-window.png"
done

export EMULATOR_API="$(adb shell getprop ro.build.version.sdk | tr -d '\r')"
export EMULATOR_ABI="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
export EMULATOR_FINGERPRINT="$(adb shell getprop ro.build.fingerprint | tr -d '\r')"
adb shell dumpsys package com.google.android.gms > tmp/google-play-services-package.txt
python3 - <<'PY'
import json
import os
import re
from pathlib import Path
from xml.etree import ElementTree

for label, package in (("boveda", "com.jlnavas3.bovedalocal"), ("monica", "takagi.ru.monica")):
    hierarchy = ElementTree.parse(Path("tmp/android-cxf-open-pair-smoke") / f"{label}-window.xml").getroot()
    visible_packages = {node.get("package") for node in hierarchy.iter("node")}
    assert package in visible_packages, f"{label} UI is not visible: {sorted(visible_packages)}"

gms_package = Path("tmp/google-play-services-package.txt").read_text(encoding="utf-8")
gms_version_name = re.search(r"\bversionName=([^\s]+)", gms_package)
gms_version_code = re.search(r"\bversionCode=(\d+)", gms_package)
assert gms_version_name and gms_version_code, "Google Play services version unavailable"

result = {
    "status": "OPEN_PAIR_INSTALL_LAUNCH_PASS",
    "scope": "Fresh emulator installation and launch only; no vault setup, credential, CXF transfer, or RP assertion.",
    "android_api": int(os.environ["EMULATOR_API"]),
    "emulator_abi": os.environ["EMULATOR_ABI"],
    "android_build_fingerprint": os.environ["EMULATOR_FINGERPRINT"],
    "google_play_services_installed": True,
    "google_play_services_version_name": gms_version_name.group(1),
    "google_play_services_version_code": int(gms_version_code.group(1)),
    "foreground_verified_for_each_app": True,
    "boveda": {
        "package": "com.jlnavas3.bovedalocal",
        "release": "v1.11.4",
        "apk_sha256": "5746092a43176e6a9e92b78a5562dc8dcd016c7007a9594f1d13f76b5d1e7d7e",
        "ui_probe_attempts": int(Path("tmp/android-cxf-open-pair-smoke/boveda-ui-attempts.txt").read_text()),
    },
    "monica": {
        "package": "takagi.ru.monica",
        "source_commit": "5ef2f3a64b53094351210f1e316fbab51852708e",
        "apk_sha256": "1ad65e8d1bf2354ed09fddfd3bd084e0aa1f67da69b7f99cdf9358dfa7f2e8f8",
        "ui_probe_attempts": int(Path("tmp/android-cxf-open-pair-smoke/monica-ui-attempts.txt").read_text()),
    },
}
assert result["android_api"] >= 34
assert result["emulator_abi"] == "x86_64"
path = Path("tmp/android-cxf-open-pair-smoke/report.json")
path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(path.read_text(encoding="utf-8"))
PY
