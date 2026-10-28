#!/usr/bin/env bash
set -euo pipefail

out=tmp/android-cxf-open-pair-onboard-probe
mkdir -p "$out"
synthetic_boveda_password=probe123456789
synthetic_monica_password=777777777777

capture() {
  label=$1
  adb shell uiautomator dump /sdcard/window.xml
  adb pull /sdcard/window.xml "$out/$label.xml"
  python3 - "$out/$label.xml" "$label" <<'PY'
import sys
from xml.etree import ElementTree
expected = "com.jlnavas3.bovedalocal" if sys.argv[2].startswith("boveda-") else "takagi.ru.monica"
packages = {node.get("package") for node in ElementTree.parse(sys.argv[1]).iter("node")}
assert expected in packages, f"Unexpected foreground package for {sys.argv[2]}: {packages}"
PY
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

assert_visible_password() {
  file=$1
  expected=$2
  python3 - "$file" "$expected" <<'PY'
import sys
from xml.etree import ElementTree
root = ElementTree.parse(sys.argv[1]).getroot()
labels = {node.get("text") for node in root.iter("node")}
assert sys.argv[2] in labels, "ADB text input did not match the synthetic value"
PY
}

type_serially() {
  value=$1
  for ((index=0; index<${#value}; index++)); do
    adb shell input text "${value:index:1}"
    sleep 0.1
  done
}

adb shell am start -W -n com.jlnavas3.bovedalocal/.ui.MainActivity > "$out/boveda-launch.txt"
sleep 3
capture boveda-before
tap_text "$out/boveda-before.xml" 'Crear mi bóveda'
sleep 3
capture boveda-after-create-tap
tap_text "$out/boveda-after-create-tap.xml" 'Contraseña maestra (protegido)'
type_serially "$synthetic_boveda_password"
adb shell input keyevent 4
capture boveda-after-first-password
tap_text "$out/boveda-after-first-password.xml" 'Repite la contraseña (protegido)'
type_serially "$synthetic_boveda_password"
adb shell input keyevent 4
capture boveda-before-forge
python3 - "$out/boveda-before-forge.xml" <<'PY'
import sys
from xml.etree import ElementTree
labels = {node.get("text") for node in ElementTree.parse(sys.argv[1]).iter("node")}
assert "✓ Las contraseñas coinciden" in labels, "Bóveda master passwords differ"
PY
tap_text "$out/boveda-before-forge.xml" 'Forjar la bóveda'
sleep 8
capture boveda-after-forge
tap_text "$out/boveda-after-forge.xml" 'Omitir por ahora'
sleep 5
capture boveda-after-skip
tap_text "$out/boveda-after-skip.xml" 'Ahora no'
sleep 5
capture boveda-after-manager-prompt
tap_text "$out/boveda-after-manager-prompt.xml" 'Nueva entrada'
sleep 3
capture boveda-new-entry-form
tap_text "$out/boveda-new-entry-form.xml" 'Título'
type_serially 'cx1'
capture boveda-entry-title
tap_text "$out/boveda-entry-title.xml" 'Usuario o correo'
type_serially 'u1'
capture boveda-entry-user
tap_text "$out/boveda-entry-user.xml" 'Contraseña (protegido)'
type_serially 'pw123'
capture boveda-entry-before-save
tap_text "$out/boveda-entry-before-save.xml" 'Guardar'
sleep 4
capture boveda-after-entry-save
tap_text "$out/boveda-after-entry-save.xml" 'Más opciones'
capture boveda-more-menu
tap_text "$out/boveda-more-menu.xml" 'Exportar...'
capture boveda-export-menu
tap_text "$out/boveda-export-menu.xml" 'Exportación directa de llaves de paso y contraseñas'
capture boveda-export-dialog
tap_text "$out/boveda-export-dialog.xml" 'Habilitar transferencia'
sleep 6
capture boveda-after-register-export

adb shell am start -W -n takagi.ru.monica/.MainActivity > "$out/monica-launch.txt"
sleep 3
capture monica-before
tap_text "$out/monica-before.xml" 'Master Password'
type_serially "$synthetic_monica_password"
adb shell input keyevent 4
capture monica-after-input
tap_text "$out/monica-after-input.xml" 'Show password'
capture monica-first-visible
assert_visible_password "$out/monica-first-visible.xml" "$synthetic_monica_password"
tap_text "$out/monica-first-visible.xml" 'Set Up Password'
sleep 3
capture monica-after-setup-tap
tap_text "$out/monica-after-setup-tap.xml" 'Confirm Master Password'
type_serially "$synthetic_monica_password"
capture monica-before-confirm
tap_text "$out/monica-before-confirm.xml" 'Show password'
capture monica-confirm-visible
assert_visible_password "$out/monica-confirm-visible.xml" "$synthetic_monica_password"
tap_text "$out/monica-confirm-visible.xml" 'Confirm'
sleep 5
capture monica-after-confirm
tap_text "$out/monica-after-confirm.xml" 'Skip'
sleep 4
capture monica-after-wizard-skip
tap_text "$out/monica-after-wizard-skip.xml" 'Set'
sleep 2
capture monica-settings

python3 - <<'PY'
import json
from pathlib import Path
from xml.etree import ElementTree

out = Path("tmp/android-cxf-open-pair-onboard-probe")
screens = {}
for label in ("boveda-before", "boveda-after-create-tap", "boveda-after-first-password", "boveda-before-forge", "boveda-after-forge", "boveda-after-skip", "boveda-after-manager-prompt", "boveda-new-entry-form", "boveda-entry-title", "boveda-entry-user", "boveda-entry-before-save", "boveda-after-entry-save", "boveda-more-menu", "boveda-export-menu", "boveda-export-dialog", "boveda-after-register-export", "monica-before", "monica-after-input", "monica-first-visible", "monica-after-setup-tap", "monica-before-confirm", "monica-confirm-visible", "monica-after-confirm", "monica-after-wizard-skip", "monica-settings"):
    root = ElementTree.parse(out / f"{label}.xml").getroot()
    screens[label] = {
        "packages": sorted({node.get("package") for node in root.iter("node") if node.get("package")}),
        "labels": [value for node in root.iter("node") if (value := node.get("text") or node.get("content-desc"))][:40],
    }
result = {
    "status": "IMPORT_NAVIGATION_PROBE_CAPTURED",
    "scope": "Synthetic local vault and basic-auth setup, Bóveda export-registration attempt, Monica settings exploration. Registration and import require inspection of captured UI. No CXF transfer, RP assertion, or PRF result.",
    "screens": screens,
}
(out / "report.json").write_text(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
PY
