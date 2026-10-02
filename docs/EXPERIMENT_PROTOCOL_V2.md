# PasskeyTransit v2 external-provider protocol

Status: prospective local protocol, frozen on 2026-10-02 **after** inspecting
the Phase 14 results and the candidate provider source, but **before** running
the provider experiment. This is a source-informed follow-up, not independent
preregistration. It does not change the v1.5 protocol or v0.7.1 release.

Machine-readable design: `experiments/protocol_v2.json`.

## Scope and units

The unit is one synthetic passkey and one specified route. The first provider
candidate is Fenko Vault 0.12.0 at commit
`2d873fbe25257250de6e322e9d785b97b17a544f`. Its published source
implements CXF import/export and a browser-extension WebAuthn provider. A CXF
file exchange is **not** a CXP protocol exchange. The experimental project
CXP/HPKE transport from Phase 14 is evaluated separately; no provider CXP
claim is permitted from the Fenko route.

The source was inspected before this protocol was written. In particular,
`src/porting/formats/cxf.ts` ignores imported `fido2Extensions` and exports an
empty object, while `src/background/prf.ts` evaluates its own PRF state. Thus
this provider is a selected loss control; its results cannot be presented as
an unbiased estimate of failure frequency across providers.

## Prespecified routes and oracles

1. **CXF import**: PasskeyTransit creates a synthetic ES256 passkey and valid CXF
   document. The unmodified provider parser/import pipeline receives it.
   Record acceptance, normalized credential ID, RP ID, user handle, public key,
   and parser warnings. Preserve only hashes and public artifacts.
2. **Browser assertion**: The provider's browser-extension path signs a fresh
   `localhost` WebAuthn challenge from the imported passkey. Verify the signed
   challenge, origin, RP ID hash, credential ID, user handle, and ES256 signature
   independently. A parser or direct Node signature alone does not satisfy
   this oracle.
3. **CXF export**: Export the imported provider record using its unmodified CXF
   exporter. Compare source and exported identity and extension representation.
   A changed item timestamp does not count as an identity failure.
4. **PRF**: For a source with two CXF HMAC seeds, evaluate the same fixed input
   twice and a second input once. For each browser-returned
   `prf.results.first`, run a second signed assertion whose challenge commits
   to the first challenge and SHA-256 of that result. Positive
   preservation requires the destination output to equal the source-standard
   PRF output for the same input and UV mode. A different output is `FAIL`
   against the source CXF seed control; unavailable execution is
   `NOT_EVALUABLE`. This comparison does not establish browser-to-browser PRF
   continuity unless the source result was also observed through WebAuthn.
   Software HMAC agreement alone is reported separately.
5. **Robustness**: Exercise one malformed-key rejection and one duplicate import
   / restart sequence against persistent provider storage. Record whether the
   first valid credential remains usable after each failure or retry. A source
   code inspection or in-memory mock cannot satisfy the storage claim.

Every oracle uses `PASS`, `FAIL`, `NOT_APPLICABLE`, or `NOT_EVALUABLE`.
Execution uses `IMPORTED`, `REJECTED`, `ERROR`, or `UNKNOWN`. Report exact case
counts and row-level evidence; no confidence interval or population estimate.
Two fresh runs test repeatability but are not independent samples.

## Evidence and claim rules

The provider source revision, source-file hashes, build command, browser
version, generated fixture hashes, and verifier hashes accompany each run.
Never persist signing keys, HMAC seeds, raw PRF outputs, or plaintext CXF
documents in a report or release. Raw synthetic secrets may exist only inside
the isolated test process/profile and are deleted with that profile.

The independent verifier must recompute identity and signature results from
retained public transcripts. If the extension result cannot be cryptographically
bound to a retained browser ceremony, report the limitation rather than
upgrading the claim. The release verifier must recompute all summaries from
rows, not only compare hashes.

Provider claims require executing the unmodified provider code, not a copied
function. Format-only, provider-behavioral, and normative CXP claims are
separate. An implementation may authenticate successfully and lose PRF; that
pair is the primary false-reassurance observation for this small follow-up.
No result is generalized to Bitwarden, other providers, or users.

## CXP and positive-PRF decision gate

After the CXF provider route, seek an open implementation that executes both
export and import CXP with passkeys. Record the exact standard revision and
wire framing. The existing Phase 14 single-document binding cannot substitute
for ZIP/JWE provider interoperability. If no runnable provider pair or test
interface is available on the host, classify CXP provider behavior as
`NOT_EVALUABLE` and retain a concrete blocker record.

A positive PRF migration requires an import interface that restores the two
CXF HMAC seeds into the authenticator/provider and returns the same WebAuthn
output for a fixed input before and after migration. CDP
`WebAuthn.addCredential` cannot meet this condition. If no such interface can
be run, keep positive PRF preservation `NOT_EVALUABLE`; do not infer failure or
success of an untested provider.

## Publication gate

The v2 manuscript can distinguish the v0.7.1 synthetic designed census,
Phase 14 post-inspection controls, and v2 provider observations. Each numerical
statement must trace to a row and exact denominator. A provider result is not
included in the v0.7.1 estimands. No new release is labeled confirmatory.
