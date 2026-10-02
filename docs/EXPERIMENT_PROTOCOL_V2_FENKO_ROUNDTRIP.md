# v2.1 source-informed browser PRF round trip

This addendum was fixed on 2026-10-02 after the Phase 15 result and after
inspecting Fenko Vault 0.12.0 source, but before executing the full browser
round trip. It is exploratory and does not amend the frozen v1.5 or v2.0
estimands. Machine-readable design:
`experiments/protocol_v2_fenko_roundtrip.json`.

Two fresh repetitions use two isolated Edge profiles each. PasskeyTransit
creates a synthetic ES256 passkey with both CXF HMAC seeds and imports it
through Fenko's file UI in source profile A. Before any source assertion,
profile A exports the credential through Fenko's CXF UI so the exported
signature counter remains zero. Profile A then executes WebAuthn PRF twice
with one input and once with another. Each result is followed by a signed
assertion whose challenge commits to the primary challenge and SHA-256 of
the returned PRF value. Profile B imports the exported CXF through Fenko's
file UI and executes the same ceremonies.

Independent verification checks RP binding, origin, credential identity,
ES256 signatures and all PRF witnesses from public transcripts. The
functional oracle is exact equality of source and destination PRF outputs
for the same salt, plus same-salt stability and changed-salt sensitivity.
Separately compare the source browser value with the software PRF computed
from the original CXF HMAC seed and record whether Fenko's exported CXF
contains that seed. No private key, HMAC seed, raw PRF value, credential ID,
or plaintext CXF export may be retained.

Source inspection predicts that Fenko will derive a provider-specific PRF
key from the signing key on each import, so same-provider browser outputs may
agree despite omission of the imported CXF seeds on export. This is a selected
mechanism check, not an unbiased discovery or a CXP provider exchange. A
positive result establishes functional continuity only for this provider,
source revision and route; it cannot establish preservation of the original
CXF HMAC seeds or interoperability with another provider. The provider's
CXF version marker is 0.0, so normative CXF conformance is not claimed.
