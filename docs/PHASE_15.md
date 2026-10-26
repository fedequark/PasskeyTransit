# Phase 15: open-source provider CXF and browser follow-up

Status: source-informed, post-Phase-14 exploratory follow-up under
`passkeytransit-external-provider-v2.0`. The design was fixed on 2026-10-02
after inspecting the selected provider's source, before this full run. It is
not independent preregistration and does not modify v0.7.1 estimands.

## Provider and route

The provider is [Fenko Vault](https://github.com/FenkoHQ/passkey-vault),
version 0.12.0, source commit
`2d873fbe25257250de6e322e9d785b97b17a544f`. Its unchanged extension
was built from pinned source and loaded into isolated Edge profiles. Two
synthetic ES256 credentials per repetition entered through Fenko's **file
import UI**, were stored by its background worker, served a real
`navigator.credentials.get()` call on `localhost`, and were exported through
its **CXF export UI**. This route tests an open provider's CXF import, browser
authentication, storage, and CXF export. It does not execute provider CXP.

The runner performed two fresh repetitions. In each it also supplied a
malformed PKCS#8 key, reimported an existing credential, restarted the browser
profile, and signed again. The PRF credential contained both CXF HMAC seeds.
For a fixed salt, the browser returned PRF twice; for a second salt, it
returned a different value. Each PRF observation was followed by a second
signed assertion whose challenge commits to the prior challenge and the
output's SHA-256 digest. The independent verifier recomputes signatures and
witness bindings from retained public transcripts.

## Observed results

| Observation | Run 1 | Run 2 |
|---|---:|---:|
| Basic and PRF credentials imported | PASS | PASS |
| Signed WebAuthn assertions and signed PRF witnesses | PASS | PASS |
| Malformed key leaves stored count unchanged | PASS | PASS |
| Duplicate import leaves stored count unchanged | PASS | PASS |
| Credential survives restart and signs | PASS | PASS |
| Same-salt PRF output stable; other salt differs | PASS | PASS |
| PRF output equals the CXF HMAC-seed standard control | FAIL | FAIL |
| Export retains `fido2Extensions.hmacCredentials` | FAIL | FAIL |

The imported credential authenticated successfully while the PRF result
diverged from the source CXF seed control. Source inspection explains the
mechanism: `src/porting/formats/cxf.ts` ignores imported `fido2Extensions`
and exports `{}`; `src/background/prf.ts` instead obtains a PRF key from the
provider's own field or SHA-256 of the signing key. This is an observed loss
for this selected provider path, not a frequency estimate or a result about
other products. The browser PRF result is in `clientExtensionResults`, not in
signed authenticator data, so the additional signed witness binds the digest
observed by the harness. It does not prove the provider's internal PRF
calculation was standards-conformant.

The export used CXF version `{major:0,minor:0}` whereas the tested profile is
CXF 1.0. It also omitted `fido2Extensions`, and the exported `userName` was
empty because the provider importer reads `userName` while the source CXF
passkey uses `username`. Credential ID and user handle were retained. These
are exact observations of this source revision, not a claim about all CXF
exporters.

## Reproduction and evidence

Clone the pinned source into the ignored `tmp/vendor_fenko` directory, then
install its pinned dependencies without package install scripts:

```powershell
git clone https://github.com/FenkoHQ/passkey-vault.git tmp/vendor_fenko
git -C tmp/vendor_fenko checkout 2d873fbe25257250de6e322e9d785b97b17a544f
Push-Location tmp/vendor_fenko
npm ci --ignore-scripts --no-audit --no-fund
Pop-Location
./research.ps1 phase15
```

The shared browser launcher explicitly removes Playwright's default
`--disable-extensions` argument before loading the pinned Fenko extension.
Without that change, Edge 154 opened a profile but no extension service
worker appeared. The corrected 2026-10-02 replay passed both provider runs
and the independent public-transcript verifier.

The script runs the provider's own CXF tests and TypeScript check, builds its
extension, performs the two browser runs, and independently verifies the
public transcripts. The retained report and verifier result are
`experiments/v2_exploratory/fenko_provider.json` and
`experiments/v2_exploratory/fenko_verification.json`. The report contains
source/build/protocol hashes, 16 signed assertions, six PRF witness bindings,
and exact storage counts. It contains no signing key, HMAC seed, raw PRF
output, plaintext CXF file, or raw credential ID. Temporary browser profiles
and downloaded CXF output are removed after each run.
The retained report SHA-256 is
`0e37480b1a045a33017a40aed67d701d0e9e5265cdb4d176dec51b7b30d11a79`.
The independent verifier recalculates the 16 signatures, six witness bindings,
source fixture digests, and exact summary counts from the two retained rows.
Storage and export observations are reported by the browser runner and checked
for internal consistency; the public transcript does not reconstruct the
provider's private database or exported plaintext document.

## Claim boundary and next gate

This provides external, browser-executed evidence for one open CXF provider.
It does not establish normative CXP interoperability or positive PRF
preservation. Positive browser-to-browser PRF remains `NOT_EVALUABLE` because
the source standard value here is a software control, not a source-provider
WebAuthn ceremony. A future positive case needs a provider/import interface
that restores both CXF HMAC seeds, followed by same-input browser PRF equality.

Bitwarden documents CXP direct import on iOS 26+ and Android 14+ through
mobile apps, with another CXP-compatible source app. No Android/iOS device,
SDK emulator, or connected mobile credential provider was available on this
Windows host during this run. Its open `credential-exchange` Rust repository
contains format and protocol models but reserves its higher-level exchange
crate. Thus the full third-party CXP provider route is currently
`NOT_EVALUABLE` here; the Phase 14 project binding cannot replace it.
The Android Codex app can access this desktop task through a remote connection,
but it does not expose the phone's credential-provider applications or passkey
store as an Android test device to the desktop harness.
For the distinction between an Android platform-mediated CXF transfer and the
public CXP Working Draft wire format, see `CXP_PROVIDER_FEASIBILITY_2026.md`.

Sources checked 2026-10-02:

- https://bitwarden.com/help/import-data/
- https://github.com/bitwarden/credential-exchange
- https://github.com/FenkoHQ/passkey-vault
- https://github.com/nuri-com/bitwarden-passkey-prf/blob/main/README.md
- https://learn.chatgpt.com/docs/remote-connections
