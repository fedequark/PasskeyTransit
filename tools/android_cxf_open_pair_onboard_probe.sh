#!/usr/bin/env bash
set -euo pipefail

out=tmp/android-cxf-open-pair-onboard-probe
mkdir -p "$out"

capture() {
  label=$1
  adb shell uiautomator dump /sdcard/window.xml
  adb pull /sdcard/window.xml "$out/$label.xml"
}

tap_text() {
  file=$1
  sought=$2
  read -r x y < <(python3 - "$file" "$sought" <<'PY'
import re
import sys
from xml.etree import ElementTree

root = ElementTree.parse(sys.argv[1]).getroot()
matches = []
for node in root.iter("node"):
    if (node.get("text") or node.get("content-desc")) == sys.argv[2]:
        values = [int(v) for v in re.findall(r"\d+", node.get("bounds", ""))]
        if len(values) == 4:
            matches.append(((values[0] + values[2]) // 2, (values[1] + values[3]) // 2))
if not matches:
    raise SystemExit(f"UI label not found: {sys.argv[2]}")
print(*max(matches, key=lambda pair: pair[1]))
PY
  )
  adb shell input tap "$x" "$y"
}

adb shell am start -W -n com.jlnavas3.bovedalocal/.ui.MainActivity > "$out/boveda-launch.txt"
sleep 3
capture boveda-before
tap_text "$out/boveda-before.xml" 'Crear mi bóveda'
sleep 3
capture boveda-after-create-tap
tap_text "$out/boveda-after-create-tap.xml" 'Contraseña maestra (protegido)'
adb shell input text 'SyntheticProbe2026'
adb shell input keyevent 4
capture boveda-after-first-password
tap_text "$out/boveda-after-first-password.xml" 'Repite la contraseña (protegido)'
adb shell input text 'SyntheticProbe2026'
adb shell input keyevent 4
capture boveda-before-forge
tap_text "$out/boveda-before-forge.xml" 'Forjar la bóveda'
sleep 8
capture boveda-after-forge

adb shell am start -W -n takagi.ru.monica/.MainActivity > "$out/monica-launch.txt"
sleep 3
capture monica-before
tap_text "$out/monica-before.xml" 'Master Password'
adb shell input text 'SyntheticProbe2026'
adb shell input keyevent 4
capture monica-after-input
tap_text "$out/monica-after-input.xml" 'Set Up Password'
sleep 3
capture monica-after-setup-tap
tap_text "$out/monica-after-setup-tap.xml" 'Confirm Master Password'
adb shell input text 'SyntheticProbe2026'
adb shell input keyevent 4
capture monica-before-confirm
tap_text "$out/monica-before-confirm.xml" 'Confirm'
sleep 5
capture monica-after-confirm

python3 - <<'PY'
import json
from pathlib import Path
from xml.etree import ElementTree

out = Path("tmp/android-cxf-open-pair-onboard-probe")
screens = {}
for label in ("boveda-before", "boveda-after-create-tap", "boveda-after-first-password", "boveda-before-forge", "boveda-after-forge", "monica-before", "monica-after-input", "monica-after-setup-tap", "monica-before-confirm", "monica-after-confirm"):
    root = ElementTree.parse(out / f"{label}.xml").getroot()
    screens[label] = {
        "packages": sorted({node.get("package") for node in root.iter("node") if node.get("package")}),
        "labels": [value for node in root.iter("node") if (value := node.get("text") or node.get("content-desc"))][:40],
    }
result = {
    "status": "SETUP_SUBMITTED_UI_CAPTURED",
    "scope": "Synthetic local vault setup submitted and final UI captured; vault creation requires inspection of final screens. No credential, CXF transfer, RP assertion, or PRF result.",
    "screens": screens,
}
(out / "report.json").write_text(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
PY
