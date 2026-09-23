# PasskeyTransit experimental protocol v1.5

Status: **frozen before the v0.7 corrective replication**

Freeze date: 2026-09-23

Protocol ID: `passkeytransit-semantic-preservation-v1.5`

## Purpose of this revision

Protocol v1.5 supersedes v1.4 after a coordinated-mutation review showed that
the public verifier could accept rewritten `largeBlob` output, oracle, semantic
class and hashes while leaving the WebAuthn signature unchanged. It also found
that the release verifier checked hashes without recomputing summaries from raw
rows, and that C3's in-memory model did not satisfy a durable-state claim.

This is a post-inspection corrective replication, not an independent
preregistered confirmation. The corpus, routes, control profiles, mutation
families, fault points and deterministic seed remain unchanged.

## Source-bound browser challenge and signed extension witness

Every imported attempt records a canonical binding containing protocol,
campaign, run, attempt, credential-ID hash, feature stratum, route, repetition,
provider chain, source SPKI hash, source user-handle hash, source RP ID and
expected origin. The challenge is:

`SHA-256("passkeytransit-webauthn-attempt-binding-v3\0" || nonce || canonical_binding)`

The nonce contains 32 fresh operating-system random bytes. The release auditor
reconstructs the challenge, requires the retained SPKI and user handle to match
the signed hashes, requires RP ID and origin to match the signed values, and
verifies the ES256 assertion. After the browser returns extension results, a
second fresh challenge commits to the first challenge hash and the canonical
extension-observation hash. A second ES256 assertion signs that witness. The
auditor verifies both ceremonies and every retained artifact hash.

## Exact designed-census summaries

C1 enumerates all 3,072 registered synthetic credential×route cells twice.
The 96 route×stratum groups are designed, balanced cells rather than a sample
from a population. Consequently v1.5 reports exact numerators, denominators and
design-weighted proportions without bootstrap intervals. It additionally emits the complete
route×stratum result matrix. Repetitions test deterministic stability; they are
not treated as independent population samples.

## Capability and claim boundary

The primary false-reassurance result remains a successful WebAuthn assertion
with failure of an executed browser oracle (`uv` or `large_blob`), with
`large_blob` protected by the signed witness. PRF and
`cred_blob` are representation-only because CDP cannot execute imported seed or
blob state. The payments marker is format-only because no SPC ceremony runs.

The C3 campaign is explicitly a simulated in-memory transaction state machine;
it does not authorize durable-storage or crash-recovery claims. Profiles remain
instrumented controls, not commercial products. CXP challenge
binding and the hybrid PQC experiment remain experimental. No population,
vulnerability, novelty or provider-superiority claim is authorized.

## Release gate

A v1.5 release requires one clean tracked source commit, complete C1/C2/C3
evidence, equivalent repetitions, 96 exact route×stratum groups, unique signed
primary and witness challenges, source-bound public keys and RP contexts,
reproduced artifact hashes, raw-to-summary recomputation, coordinated-mutation
tests, a scoped licensed source snapshot and complete release-hash verification.
