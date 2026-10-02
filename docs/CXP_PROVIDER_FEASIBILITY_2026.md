# CXP provider feasibility and evidence boundary (2026-10-02)

This is a post-Phase-16 feasibility audit, not an experiment and not an
amendment to the frozen v1.5 or v2.0 protocols. Its purpose is to identify
what a future external-provider run could prove on an actual platform.

## Two different exchange claims

The public FIDO CXP specification available on 2026-10-02 is the 2024-10-03
Working Draft. It describes a JSON export request/response and a ZIP payload
whose credential files are JWE-encrypted. The public specification directory
does not list a newer CXP level. Its narrative refers to a signed challenge
and an exporter migration key, but those members are absent from the displayed
request/response object schemas. PasskeyTransit therefore uses a separately
labelled experimental binding for its Phase 4/14 transport; matching that
binding is not normative CXP provider interoperability.

Android's *Credentials Transfer APIs* describe a different observable
application boundary: the exporter returns a CXF JSON string through an
Android-brokered Content URI, and the importer receives that JSON string from
`ProviderEventsManager.importCredentials()`. The API is mediated by the
platform/Google Play services and is not documented as exposing the Working
Draft ZIP/JWE wire framing to either application. A successful transfer
between Android apps would prove a platform-mediated CXF provider flow and
passkey behavior. Without a captured normative CXP request, response and
encrypted archive, it would not prove the public CXP Working Draft framing.

Bitwarden calls its direct mobile flow CXP and documents it for iOS 26+ and
Android 14+ with another compatible app. Keyguard documents CXF v1.0 import
and export over the Android transfer mechanism, including passkeys, and says
the path requires Google Play services and an Android source provider on
Android 14+. Keyguard→Bitwarden is a plausible identified *platform transfer*
candidate, not a completed experiment or proof of normative CXP transport.
Keyguard is a separate client for the Bitwarden platform (and KeePass files),
so the trial would need separate synthetic source and destination vaults to
avoid mistaking shared backend state for migration. Its source is published
for personal use only; it does not satisfy an open-source-licensed-provider
selection criterion.

| Claim | Minimum evidence | Current state |
|---|---|---|
| External CXF import, browser authentication and CXF export | Provider UI and signed browser assertions | Fenko Phase 15: measured |
| Same-provider browser PRF continuity over CXF | Signed source/destination PRF observations | Fenko Phase 16: measured |
| Android platform-mediated transfer between distinct provider apps | Two identified apps on a live Android/Play-services environment with separate vaults, transfer receipt, retained identity and signed destination assertion | Not evaluated |
| Public CXP Working Draft wire interoperability | Captured request/response, selected HPKE parameters, ZIP/JWE payload, independent recipient, negative controls | Not evaluated |
| Browser-to-browser preservation of original CXF HMAC seeds | Original source-browser PRF, restored destination-browser PRF on the same inputs, seed-state trace | Not evaluated positively; selected Fenko route failed against the source CXF seed control |

After this audit, Phase 17 executed Proton Pass 2.0.0's published worker
WASM. Its independent CXF import/export/reimport preserved both original HMAC
seed byte strings and its software authenticator returned the expected UV PRF.
This adds a positive software control, but the source-browser to
destination-browser and two-provider CXP rows above remain unevaluated.

## Environment and next executable route

On this Windows host, `adb`, Android Emulator, Android SDK, Java, Docker and
Cargo were not available in the command path during the audit. No Android
device is attached to the harness. The Android Codex app is a remote view of
this desktop task and supplies no interface to the phone's credential
providers. Installing an emulator
alone would not establish a working Play-services transfer or give the
harness access to two seeded provider apps; those preconditions must be
verified before attempting a mobile run.

An actual provider experiment should use synthetic passkeys only, record the
Android and Play-services versions, both app versions and source revisions,
and capture source/destination WebAuthn transcripts against a controlled RP.
The transfer itself needs a user-approved source and destination app session;
app accounts or personal credentials are not part of this research fixture.
Record the source/provider receipt, import result, credential identity,
signature verification, duplicate/retry behavior and PRF support per app.
Classify unavailable PRF as `NOT_EVALUABLE`, rather than treating a successful
basic login as PRF preservation. If the platform does not expose payload
bytes, label the format-state oracle `NOT_EVALUABLE` and rely only on
observable browser/provider behavior for that run.

The open `go-cxp` package publishes protocol data types but no package-level
functions; the Bitwarden `credential-exchange` high-level crate is reserved.
Neither is an executable independent provider exporter/importer by itself.
Proton Pass 2.0.0 does include executable CXP import/export handlers in its
source tree; the published worker WASM exposes CXF import/export but not those
CXP handlers. Its source handler encrypts CXF JSON directly with HPKE, so an
execution of that route would still need a separately qualified claim against
the public Working Draft's ZIP/JWE payload.

KeePassDX is GPL-licensed and advertises passkey PRF, but its own import/export
documentation explicitly says CXF is still under development. It therefore
cannot currently be selected as an executable CXF migration route based on
that documentation alone.

## Primary sources checked 2026-10-02

- FIDO Alliance, public CX specification directory:
  https://fidoalliance.org/specs/cx/
- FIDO Alliance, CXP v1.0 Working Draft 2024-10-03:
  https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html
- Android Developers, Credential transfer:
  https://developer.android.com/identity/sign-in/credential-transfer
- Bitwarden, Import to your Vault or Collections:
  https://bitwarden.com/help/import-data/
- Keyguard, Credential Exchange:
  https://keyguard.dev/docs/credential-exchange/
- Keyguard, project description and license:
  https://github.com/AChep/keyguard-app
- Bitwarden, credential-exchange source:
  https://github.com/bitwarden/credential-exchange
- go-cxp public API:
  https://pkg.go.dev/github.com/nvinuesa/go-cxp
- OpenAI, remote connections:
  https://learn.chatgpt.com/docs/remote-connections
- Proton Pass common 2.0.0, pinned source:
  https://github.com/protonpass/proton-pass-common/tree/69a0927f0fe7071243d6c38e404459a69210fdd4
- KeePassDX, import/export status:
  https://github.com/Kunzisoft/KeePassDX/wiki/Import-and-Export
- KeePassDX, changelog:
  https://github.com/Kunzisoft/KeePassDX/blob/master/CHANGELOG
