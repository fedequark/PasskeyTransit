# PasskeyTransit experimental protocol v1.3

Status: **frozen before the v0.5 corrective replication**

Freeze date: 2026-09-23

Protocol ID: `passkeytransit-semantic-preservation-v1.3`

## Purpose of this revision

Protocol v1.3 supersedes v1.2 for new evidence. Results from v1.2 and the review
that challenged them were inspected before this revision. The v0.5 campaign is
therefore another corrective replication under a post-inspection protocol, not
an independent preregistered confirmation.

The revision retains the corpus, routes, control profiles, strict rejection
rule, mutation families, fault points and deterministic design seed. It changes
the estimand capability classes, signed challenge construction and retained
extension evidence.

## Capability-separated estimands

The primary false-reassurance estimand is a successful WebAuthn assertion with
at least one failed browser-executed behavioral oracle. Only `uv` and
`large_blob` belong to this set.

`prf_uv`, `prf_no_uv` and `cred_blob` are nonexecuted representation oracles.
The harness can establish that required source material is absent after a route,
but CDP cannot inject and execute preserved material. `payments_marker` is a
format-only oracle because the harness does not execute Secure Payment
Confirmation.

The release reports four overlapping quantities with explicit numerators and
denominators:

1. browser-executed false reassurance;
2. login with nonexecuted representation loss;
3. login with any non-payment property failure; and
4. login with any observed property failure, including the payments marker.

## Signed attempt binding

For every authentication ceremony, the harness generates a fresh 32-byte nonce
with the operating-system cryptographic random generator. It constructs a
canonical context containing protocol, campaign, run, attempt, credential hash,
feature stratum, route, repetition and provider chain. The signed WebAuthn
challenge is:

`SHA-256(domain || nonce || canonical_context)`

The domain is `passkeytransit-webauthn-attempt-binding-v1` followed by a zero
byte. The retained transcript contains the nonce and context. The release
auditor reconstructs the challenge, compares the context with the row and
checks that the credential ID in the assertion hashes to the row credential
hash. Reassigning a transcript to another row must fail even if an attacker
rewrites the context and recomputes unkeyed artifact hashes.

## Retained largeBlob observation

For every imported attempt, the public evidence records whether `largeBlob` is
applicable and retains its expected and browser-observed values. These are
synthetic bytes and contain no user secret. The auditor recomputes the
`large_blob` oracle status and its evidence hashes from those values.

The client-extension result is an observation of the instrumented browser API;
it is not an authenticator-signed extension output. The signed challenge binds
the core WebAuthn ceremony to the row, while the release manifest commits the
complete retained row and extension observation.

## Preserved design and claim boundary

C1 contains 3,072 designed synthetic credential-by-route cells, each executed
twice. C2 contains 80 mutation cases and C3 contains 960 fault sequences. The
cluster-bootstrap intervals remain descriptive sensitivity summaries rather
than population confidence intervals.

The provider labels are instrumented controls rather than commercial products.
Positive PRF and `credBlob` behavior remains non-evaluable through CDP. The CXP
binding and hybrid PQC experiment remain experimental.

## Release gate

A v1.3 release is admissible only when all evidence names one clean tracked
source commit, all 6,144 C1 rows are present, repetitions agree, every imported
transcript passes signed context reconstruction, all challenges are unique,
every `largeBlob` oracle is reproduced from retained values, all four estimands
are emitted, adversarial transcript-reassignment tests pass and every release
hash verifies.
