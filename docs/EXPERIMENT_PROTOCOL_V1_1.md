# PasskeyTransit experimental protocol v1.1

Status: **frozen before the corrected v0.3 confirmatory campaign**

Freeze date: 2026-09-23

Protocol ID: `passkeytransit-semantic-preservation-v1.1`

## Purpose of this revision

Protocol v1.1 supersedes v1.0 for new evidence. It preserves the research
questions, corpus, routes, mutation families, fault points and registered seed.
It corrects the strict-profile operational rule, makes the designed units
explicit, and requires retention of independently verifiable browser evidence.
Historical v1.0 evidence remains immutable and must be labelled superseded.

## Strict profile rule

At every hop into `strict`, the importer compares the candidate with the source
ground truth. If identity, key material or an applicable required property was
lost at an earlier hop, `strict` rejects the import before persistence and before
the WebAuthn ceremony. A rejected attempt is `REJECTED` on the execution axis
and `NOT_APPLICABLE` on the semantic-preservation axis. It is never counted as
an imported credential, an assertion attempt or a semantic pass.

## Units and uncertainty

C1 contains 3,072 unique synthetic `credential × route` cells: 256 credentials
and 12 routes. Each cell is executed twice, producing 6,144 attempts. Results
are also summarized in 96 `route × feature-stratum` reporting groups. The exact
repetitions check deterministic stability and do not add independent empirical
units.

Credentials, routes and provider profiles are designed controls rather than a
sample from a real-world population. Cluster bootstrap intervals are retained
only as descriptive sensitivity analyses over the designed credential corpus.
They are not population confidence intervals and do not authorize prevalence,
vendor or product claims.

## Browser evidence rule

Every imported browser attempt retains the public WebAuthn verification inputs:
raw credential identifier, authenticator data, client data JSON, signature,
user handle, source public key, source RP ID and expected origin. The row also
contains the independent Boolean checks and a SHA-256 commitment to the
canonical transcript. Private keys, PRF secrets and application blob plaintext
are not published.

The release verifier must establish that every imported attempt contains a
transcript, that its commitment matches, and that independent re-verification
reproduces the recorded assertion outcome.

## Threat model

The transport experiment considers an observer or active modifier of the
exchange channel who lacks the importer's private key. The importer and the
instrumented control profiles are trusted. The experimental binding checks
request mix-up, contextual modification, downgrade and replay within local
state.

The experiment does not claim protection against compromised endpoints,
private-key extraction, side channels, deceptive UI, colluding providers or
loss of durable antireplay state. HPKE base mode does not authenticate exporter
identity. User authorization, provider attestation and commercial backup or
deletion semantics remain outside the tested security boundary.

## Preserved sections from v1.0

The objective, RQ1-RQ4, eight feature strata, four provider labels, twelve
routes, oracle vocabulary, C2 mutation families, C3 fault points, exclusion
rules and claim boundaries remain as specified in
`docs/EXPERIMENT_PROTOCOL.md`. The complete executable configuration is
`experiments/protocol_v1.1.json`; where the documents differ, v1.1 governs new
evidence.

## Release gate

A v1.1 result is confirmatory only when all campaign and interoperability
manifests name one clean tracked source commit, the complete C1 run has 6,144
attempt rows, exact repetitions agree on registered outcome fields, all
published hashes verify, and the release contains exactly one canonical
analysis manifest.
