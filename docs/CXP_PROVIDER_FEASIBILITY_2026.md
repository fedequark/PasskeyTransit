# CXP provider feasibility and evidence boundary (2026-10-02)

This is a post-Phase-16 feasibility audit, not an experiment and not an
amendment to the frozen v1.5 or v2.0 protocols. Its purpose is to identify
what a future external-provider run could prove on an actual platform.

## Recheck 2026-10-20

The [FIDO public specification directory](https://fidoalliance.org/specs/cx/)
still lists the 2024-10-03 Working Draft as its latest public CXP document.
The auditable Phase 14 replay added independently verifiable browser
signatures, but it still tests the project's binding rather than the public
ZIP/JWE wire profile or a second provider. A same-host fresh-venv reproduction
of the review ZIP passed; it is not a third-party replication.

An additional open [KeePassPasskey Windows provider](https://github.com/yusei36/KeePassPasskey)
is now a possible *browser-provider* candidate: its documentation says it
integrates with Windows 11's native passkey provider interface and shares a
KeePassXC-compatible passkey field format. Its documented fields do not show
CXF HMAC-seed import/export or a CXP endpoint, so it is not yet a candidate
for the public CXP wire claim or positive PRF seed migration. It requires
KeePass, plugin installation and Windows provider registration; none was
installed or tested during this audit. A controlled pilot would need to check
PRF support and CXF semantics before any result claim.

## Desktop provider screen, 2026-10-20

The [KeePassPasskey project README](https://github.com/yusei36/KeePassPasskey)
documents a native Windows 11 24H2+ provider, with KeePass 2.54+ and TPM
as prerequisites. It registers an MSIX COM provider and a KeePass plugin.
Its documented storage fields are credential ID, PKCS#8 private key, RP ID,
username, user handle, and backup flags. The README does not document CXF
import/export, HMAC seeds, WebAuthn PRF behavior, or a CXP endpoint. Absence
from that document is an **unknown capability**, not a measured failure.
Its KeePassXC-compatible field format could enable a basic signing-key
continuity pilot, but a field-format copy would not establish a CXF transfer.

On this host, the OS build reports 10.0.26300, while direct WMI inspection
and WSL access were denied. No KeePass executable was found on PATH, and
the provider was not installed or registered. A source clone from the shell
failed because this sandbox could not resolve github.com; the screen above
uses the project's published README only. Installing the MSIX/plugin and
enabling a Windows credential provider changes system state and was not
done. This route is therefore **feasibility-screened, not executed**.

The narrowest future result would be a signed WebAuthn assertion from a
synthetic KeePassPasskey credential. A CXF claim requires a demonstrated
CXF import/export interface and seed comparison. A CXP claim additionally
requires two independent endpoints and captured protocol framing. A PRF
claim requires a browser PRF result and a seed-derived oracle, or an explicit
NOT_EVALUABLE outcome. No paper result is inferred from this screen.

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

Bitwarden calls its direct mobile flow CXP. Its current help describes direct
export on Android 10+, while its direct-import instructions require Android
14+; iOS transfer requires iOS 26+. Keyguard documents CXF v1.0 import
and export over the Android transfer mechanism, including passkeys, and says
the path requires Google Play services and an Android source provider on
Android 14+. Keyguard→Google Password Manager is now the selected *platform
transfer* candidate, not a completed experiment or proof of normative CXP
transport. The synthetic Bitwarden test vault is visible in Keyguard, while
Google Password Manager is a separate destination; a pre-import absence check
is needed so Bitwarden server sync cannot explain a result. Bitwarden's Terms
of Service allow one free account per person, so the earlier two-free-account
Bitwarden design was withdrawn. Keyguard's source is published for personal
use only; it does not satisfy an open-source-licensed-provider criterion.

| Claim | Minimum evidence | Current state |
|---|---|---|
| External CXF import, browser authentication and CXF export | Provider UI and signed browser assertions | Fenko Phase 15: measured |
| Same-provider browser PRF continuity over CXF | Signed source/destination PRF observations | Fenko Phase 16: measured |
| Android platform-mediated transfer between distinct provider apps | Two identified apps on a live Android/Play-services environment with separate vaults, transfer receipt, retained identity and signed destination assertion | One operator report and two contextual screenshots; exploratory feasibility anecdote, excluded from manuscript results; independent verification NOT_EVALUABLE |
| Public CXP Working Draft wire interoperability | Captured request/response, selected HPKE parameters, ZIP/JWE payload, independent recipient, negative controls | Not evaluated |
| Browser-to-browser preservation of original CXF HMAC seeds | Original source-browser PRF, restored destination-browser PRF on the same inputs, seed-state trace | Not evaluated positively; selected Fenko route failed against the source CXF seed control |

After this audit, Phase 17 executed Proton Pass 2.0.0's published worker
WASM. Its independent CXF import/export/reimport preserved both original HMAC
seed byte strings and its software authenticator returned the expected UV PRF.
This adds a positive software control, but the source-browser to
destination-browser and two-provider CXP rows above remain unevaluated.

## Environment and next executable route

On this Windows host, `adb`, Android Emulator, Android SDK, Java and Docker
were not available in the command path during the audit. Cargo was initially
absent from `PATH`, but a Rust GNU toolchain was subsequently located at
`C:\Users\fedep\.rustup\toolchains\stable-x86_64-pc-windows-gnu\bin` and its
`cargo`/`rustc` 1.98.1 executables were confirmed. The attempted local Proton
native build did not yield an executable CXP adapter: Windows Application
Control blocked generated build-script executables (error 4551), and the GNU
linker toolchain lacked `dlltool.exe`. This is a host execution limit, not a
claim that Proton's source cannot compile elsewhere. No Android device is
attached to the harness. The Android Codex app supplies no interface to this
phone's credential providers from the desktop task. Installing an emulator
alone would not establish a working Play-services transfer or give the
harness access to two seeded provider apps; those preconditions must be
verified before attempting a mobile run.

A collaborator has operated an Android 14+ phone manually. They reported
registering one synthetic passkey in a Bitwarden test vault and seeing it in
Keyguard. They removed a preexisting matching synthetic item from Google
Password Manager before the attempted import. Keyguard reportedly shared no
items; Bitwarden's source review reported "1 passkey", yet Google Password
Manager reported nothing to import. A single retry after instructions to
select Google as the Android passkey provider gave the same operator-reported
result; the provider selection was not independently verified. A later attempt
added a synthetic `pqc1` Login as a control. The operator reports that Google
Password Manager imported it as a Password but still did not list the original
webauthn.io passkey. The procedure and observation form are in
`docs/ANDROID_FIELD_RUNBOOK.md`. The control supports only an ordinary-login
transfer observation. For a new `pqc2` passkey, created with Bitwarden after
checking that Google had no matching item, the operator subsequently reported
successful import into Google Password Manager and successful webauthn.io
authentication after selecting Google as Android's provider. This is a
exploratory self-report for Bitwarden→Google on one synthetic credential.
Two later screenshots show a `pqc2` passkey item in a manager screen identified
by the operator as Google Password Manager and the webauthn.io credential
profile. The profile's Bitwarden AAGUID describes registration metadata, not
the manager that supplied a subsequent assertion. No provider receipt or
signed browser transcript was retained. This anecdote is excluded from the
v0.8 manuscript's measured results. The first passkey's omission remains
unexplained. Independently verified passkey continuity, normative CXP wire
behavior and PRF preservation remain `NOT_EVALUABLE`.

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

## Desktop alternative screen

The Keyguard project states that it has no browser extension. Its documented
CXF passkey transfer route is Android platform-mediated, so it does not supply
a second browser provider for the present Windows harness. The open
`authenticator-sh/2fa` extension advertises CXF import/export, but inspection
of its `src/utils/cxf.ts` shows that it serializes and imports TOTP credentials
only. Its passkey feature uses WebAuthn PRF to unlock its own TOTP vault; it is
not a passkey credential provider and explicitly does not implement CXP. These
are candidate exclusions based on published code and documentation, not
negative interoperability measurements.

## Primary sources checked 2026-10-02

- FIDO Alliance, public CX specification directory:
  https://fidoalliance.org/specs/cx/
- FIDO Alliance, CXP v1.0 Working Draft 2024-10-03:
  https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html
- Android Developers, Credential transfer:
  https://developer.android.com/identity/sign-in/credential-transfer
- Bitwarden, Import to your Vault or Collections:
  https://bitwarden.com/help/import-data/
- Bitwarden, Export Vault Data:
  https://bitwarden.com/help/export-your-data/
- Bitwarden, Terms of Service (one free account per person or entity):
  https://bitwarden.com/terms/
- Keyguard, Credential Exchange:
  https://keyguard.dev/docs/credential-exchange/
- Google Chrome Help, import/export passwords and passkeys on Android:
  https://support.google.com/chrome/answer/13068232?co=GENIE.Platform%3DAndroid
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
- Authenticator extension, CXF implementation:
  https://github.com/authenticator-sh/2fa/blob/main/src/utils/cxf.ts
- Authenticator extension, stated passkey and CXP scope:
  https://github.com/authenticator-sh/2fa
