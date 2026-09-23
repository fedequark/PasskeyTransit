# PasskeyTransit experimental protocol v1.4

Status: **frozen before the v0.6 corrective replication**

Freeze date: 2026-09-23

Protocol ID: `passkeytransit-semantic-preservation-v1.4`

## Purpose of this revision

Protocol v1.4 supersedes v1.3 after an adversarial review showed that the public
browser verifier accepted a replacement signing key when the transcript was
resigned and its unkeyed commitment was recomputed. The original generation
path verified with the source key, but the retained evidence did not bind that
key or the complete RP context into the signed challenge.

This is a post-inspection corrective replication, not an independent
preregistered confirmation. The corpus, routes, control profiles, mutation
families, fault points and deterministic seed remain unchanged.

## Source-bound browser challenge

Every imported attempt records a canonical binding containing protocol,
campaign, run, attempt, credential-ID hash, feature stratum, route, repetition,
provider chain, source SPKI hash, source user-handle hash, source RP ID and
expected origin. The challenge is:

`SHA-256("passkeytransit-webauthn-attempt-binding-v2\0" || nonce || canonical_binding)`

The nonce contains 32 fresh operating-system random bytes. The release auditor
reconstructs the challenge, requires the retained SPKI and user handle to match
the signed hashes, requires RP ID and origin to match the signed values, and
verifies the ES256 assertion. It also reproduces every retained artifact hash.

## Exact designed-census summaries

C1 enumerates all 3,072 registered synthetic credential×route cells twice.
The 96 route×stratum groups are designed, balanced cells rather than a sample
from a population. Consequently v1.4 reports exact numerators, denominators and
proportions without bootstrap intervals. It additionally emits the complete
route×stratum result matrix. Repetitions test deterministic stability; they are
not treated as independent population samples.

## Capability and claim boundary

The primary false-reassurance result remains a successful WebAuthn assertion
with failure of an executed browser oracle (`uv` or `large_blob`). PRF and
`cred_blob` are representation-only because CDP cannot execute imported seed or
blob state. The payments marker is format-only because no SPC ceremony runs.

Profiles remain instrumented controls, not commercial products. CXP challenge
binding and the hybrid PQC experiment remain experimental. No population,
vulnerability, novelty or provider-superiority claim is authorized.

## Release gate

A v1.4 release requires one clean tracked source commit, complete C1/C2/C3
evidence, equivalent repetitions, 96 exact route×stratum groups, unique signed
challenges, source-bound public keys and RP contexts, reproduced artifact and
largeBlob hashes, adversarial substitution tests, a licensed source snapshot
and complete internal and external release-hash verification.
