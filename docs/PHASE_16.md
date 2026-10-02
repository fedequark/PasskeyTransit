# Phase 16: positive same-provider browser PRF continuity control

Status: source-informed exploratory follow-up to Phase 15. The addendum
`docs/EXPERIMENT_PROTOCOL_V2_FENKO_ROUNDTRIP.md` was written after inspecting
Fenko Vault 0.12.0 and before the browser run. It does not change the v1.5
campaign or the v2.0 selected loss case.

## Route

Two fresh repetitions each used two isolated Edge 154 profiles with the same
unchanged Fenko Vault 0.12.0 extension at commit
`2d873fbe25257250de6e322e9d785b97b17a544f`. PasskeyTransit supplied a
synthetic CXF passkey with two HMAC seeds to profile A. A exported it through
Fenko's CXF UI before any assertion, leaving the exported signature counter
at zero. Profile B imported that file through Fenko's import UI. In both
profiles the browser called `navigator.credentials.get()` for a fixed PRF
input twice and for a different input once. Every PRF observation was
followed by a signed assertion committing to its SHA-256 digest.

| Independently checked observation | Result |
|---|---:|
| Source and destination signed assertions | 24/24 verified |
| PRF digest witness bindings | 12/12 verified |
| Same-input source and destination PRF equality | 2/2 repetitions |
| Same-salt stability and other-salt difference in both profiles | 2/2 repetitions |
| Source browser PRF matches original CXF HMAC-seed control | 0/2 repetitions |
| Exported CXF retains original HMAC extension state | 0/2 repetitions |

The functional continuity oracle was `PASS` in both repetitions. The source
CXF seed oracle was `FAIL` in both. Source inspection explains their
coexistence: Fenko ignores incoming CXF `fido2Extensions`, derives its PRF key
from the signing key when needed, and omits extension state from its CXF
export. Both profiles can therefore return the same provider-specific PRF
value without preserving the original seed. The exported CXF uses version
`{major:0,minor:0}`, outside the tested CXF 1.0 profile. This is evidence of
same-provider functional continuity, not of normative CXF conformance,
seed preservation, independent-provider interoperability, or CXP.

## Reproduce and verify

Prepare the pinned Fenko source as in `docs/PHASE_15.md`, then run:

```powershell
./research.ps1 phase16
```

The script runs Fenko's CXF tests and typecheck, builds the unchanged
extension, runs two browser round trips and independently recalculates public
transcripts. Retained files are
`experiments/v2_roundtrip_exploratory/fenko_roundtrip.json` and
`experiments/v2_roundtrip_exploratory/fenko_roundtrip_verification.json`.
Report SHA-256:
`ea3133ecdf31973766b304d0c92896afaca939ee7dcdeb07a5b268889a7ead50`.
The report retains source/build/protocol hashes, browser version, public
assertions and PRF digests. It excludes signing keys, HMAC seeds, raw PRF
outputs, credential IDs and plaintext CXF documents. Both temporary
profiles and the downloaded CXF file are removed after each run. The public
verifier recalculates signatures and PRF equality from retained digests; it
checks import/export summaries for consistency but cannot reconstruct the
provider's private storage.

## Remaining gate

A second independent provider with executable CXP export/import is still
needed for the provider CXP claim. A positive *standard CXF seed*
preservation case needs an importer that restores both HMAC seeds and a
source/destination browser ceremony with the same input. Neither result can
be inferred from this same-provider control.
