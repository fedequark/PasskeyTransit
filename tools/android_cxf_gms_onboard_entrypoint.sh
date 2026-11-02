#!/usr/bin/env bash
set -euo pipefail

if python tools/android_cxf_gms_preflight.py --output tmp/android-cxf-gms-preflight/report.json; then
  bash tools/android_cxf_open_pair_smoke.sh
  bash tools/android_cxf_open_pair_onboard_probe.sh
else
  code=$?
  if [ "$code" -ne 2 ]; then
    exit "$code"
  fi
  echo 'Provider-events UI probe skipped: installed Google Play services is below AndroidX minimum.'
fi
