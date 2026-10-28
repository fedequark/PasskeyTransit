# Android CXF emulator bootstrap with public-source apps

Keyguard is source-available and commercially licensed; Monica is open source. Keyguard's premium gate prevented an authorized vault setup in this smoke test.

Checked 2026-10-26. [CI run 40374032112](https://github.com/fedequark/PasskeyTransit/actions/runs/40374032112) completed on a fresh Android 15 / API 35 `x86_64` emulator with a Google Play Store system image. Google Play services was installed. This is an **installation and foreground launch control**, not a credential-transfer result.

| Provider APK | Provenance | Observed |
|---|---|---|
| Keyguard | Published release [`r20261024.1`](https://github.com/AChep/keyguard-app/releases/tag/r20261024.1), SHA-256 `58c018583b5e1d1b0e22dcdd21a9de29fde44988934a37c194cba92905b79763` | Installed as `com.artemchep.keyguard`; process remained alive after launch. Its first screen offered “Create a vault” and required confirmation of a purchased or active license. No such confirmation was made. |
| Monica | [Pinned source `5ef2f3a`](https://github.com/Monica-Pass/Monica/tree/5ef2f3a64b53094351210f1e316fbab51852708e), built for `x86_64` by [CI run 40371271466](https://github.com/fedequark/PasskeyTransit/actions/runs/40371271466); APK SHA-256 `1ad65e8d1bf2354ed09fddfd3bd084e0aa1f67da69b7f99cdf9358dfa7f2e8f8` | Installed as `takagi.ru.monica`; process remained alive after launch. Its first screen asked to set a master password. No password was entered. |

The [retained report](../experiments/android_cxf_emulator_smoke/report.json) and two UI hierarchy XML files came from the CI artifact `android-cxf-emulator-smoke`, digest `sha256:09425d5a3be03da2ca3b158f3beb08aa67f4de511bdbfe39467566cdf597594b`. Retained file SHA-256 values are `7ace9b5433dc1747e5719102799d33cedaad971392cb56bf21a4fe651be6408a` (report), `a527715fc0a15898a333a496ef2cecee1fc8ab5cb42f78abb7bfcea5423b71c2` (Keyguard XML), and `4fbf22ca68fa8577ef96b55087bd1e4a896e043f5faa742fc9184e519fc671de` (Monica XML). The [workflow](../.github/workflows/android-cxf-emulator-smoke.yml) and [script](../tools/android_cxf_emulator_smoke.sh) recreate the control while the APK sources remain accessible.

No passkey, local vault, provider-events exchange, import receipt, WebAuthn assertion, or PRF check was attempted. The Keyguard license prompt is a prerequisite to resolve before a vault test; the result must not be represented as Android CXF interoperability. The two APKs also correspond to different source revisions; the earlier [CXF source audit](ANDROID_CXF_OPEN_AUDIT.md) remains a separate, narrower observation.
