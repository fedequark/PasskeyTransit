# PasskeyTransit experimental protocol v1.0

Status: **frozen before v0.2 implementation and confirmatory data collection**  
Freeze date: 2026-09-12  
Protocol ID: `passkeytransit-semantic-preservation-v1.0`

## 1. Objective

Determine whether a passkey that is accepted after credential exchange retains
the identity, cryptographic operation, extension behavior, and operational
properties required by its source ground truth. The study evaluates reference
implementations and explicitly identified implementations; it does not infer
the behavior of untested commercial products.

The central falsifiable proposition is:

> Successful import and successful basic authentication are insufficient to
> establish semantic preservation of every applicable passkey property.

## 2. Research questions

### RQ1 — Direct preservation

To what extent do direct migrations preserve passkey identity, public-key
correspondence, and an assertion accepted by the original relying party?

### RQ2 — Functional preservation and false reassurance

Among accepted imports, which applicable functions are preserved, and how often
does basic authentication pass while at least one other required function fails?

### RQ3 — Path dependence

For the same source credential and final provider, does the preservation result
change when one or more intermediate providers are introduced or when the
credential completes a round trip?

### RQ4 — Robustness and recovery

How do implementations handle unknown values, version mismatch, duplicate
imports, malformed data, and failures injected before commit or during retry?

Custody visibility and user comprehension remain exploratory because synthetic
storage instrumentation can count copies but cannot establish what a real user
understands or what an opaque commercial backup system retains.

## 3. Study object and unit of analysis

The source population is a designed corpus of synthetic, discoverable ES256
passkeys. ES256 is fixed for the primary study because the planned Chromium CDP
credential-injection path accepts P-256 PKCS#8 private keys. Other algorithms
will be reported only as secondary parser/importer tests until an equivalent
end-to-end execution path exists.

The primary unit is one `credential × route × environment × repetition`
attempt. Repeated attempts involving the same credential are not treated as
statistically independent.

The fault-injection unit is one complete attempt sequence: initial import,
injected failure, observed state, retry when applicable, and final state.

## 4. Fixed factors

### Credential strata

The confirmatory corpus contains 256 credentials: 32 deterministic credentials
in each of eight strata.

| ID | Required properties |
|---|---|
| F0 | Basic discoverable ES256 credential |
| F1 | HMAC credentials exercised through WebAuthn PRF with UV |
| F2 | HMAC credentials exercised through WebAuthn PRF without UV |
| F3 | `largeBlob` |
| F4 | `credBlob` |
| F5 | payments/SPC marker; operational ceremony is secondary if automation is unavailable |
| F6 | PRF with UV plus `largeBlob` and `credBlob` |
| F7 | Known properties plus one forward-compatible unknown optional member |

Every byte-valued property includes boundary cases selected before execution.
Malformed cases are excluded from this valid-source corpus and belong to the
separate robustness campaign.

### Provider profiles

- `reference`: lossless implementation used to establish the harness oracle.
- `strict`: rejects an import when a required property cannot be preserved.
- `compatible-lossy`: may accept representable data but must declare every
  unsupported applicable property before commit.
- `legacy`: lacks selected extension capabilities and is used as a controlled
  degradation stimulus.

These labels describe versioned policies, not vendors.

### Routes

Twelve routes are frozen in `experiments/protocol_v1.0.json`: three direct,
three round-trip, four two-destination multihop, and two longer multihop routes.
Route pairs ending at the same provider permit matched path-dependence analysis.

## 5. Oracles and applicability

Each oracle returns `PASS`, `FAIL`, `NOT_APPLICABLE`, or `NOT_EVALUABLE` plus
machine-readable evidence.

| Class | Oracle |
|---|---|
| Structural | CXF validation against the Phase 2 requirement matrix |
| Identity | byte equality of `credentialId`, `rpId`, and `userHandle` |
| Cryptographic | imported private key derives the registered public key |
| WebAuthn | assertion verifies against the original RP record and challenge |
| UV | requested UV semantics and returned UV flag are preserved |
| PRF | outputs match for fixed and generated salts, separately with/without UV |
| `largeBlob` | decompressed application bytes match ground truth |
| `credBlob` | retrieved credential blob bytes match ground truth |
| Payments | marker preservation; real SPC behavior only if executable |
| Idempotence | retry converges to one semantically equivalent credential state |
| Atomicity | failure produces full commit or complete rollback |
| Custody | instrumented provider copy set only; opaque deletion is not inferred |

An unsupported property is still applicable when the protocol or provider
claims it will be preserved. It is `NOT_APPLICABLE` only when absent from the
source credential and not required by the test case. `NOT_EVALUABLE` is never
counted as success and its cause must be reported.

## 6. Outcome model

Three independent axes are recorded to prevent category errors.

### Execution status

`IMPORTED`, `REJECTED`, `ROLLED_BACK`, `PARTIAL`, `ERROR`, or `UNKNOWN`.

### Semantic preservation

- `PASS`: every applicable required oracle passes.
- `DEGRADED_VISIBLE`: import completes, at least one applicable oracle fails,
  and the loss was declared in machine-readable form before commit.
- `DEGRADED_SILENT`: import completes and an applicable oracle fails without
  an adequate pre-commit declaration.
- `NOT_APPLICABLE`: no semantic preservation claim applies to the case.
- `NOT_EVALUABLE`: the harness cannot determine the result.

### Normative assessment

`CONFORMANT`, `VIOLATION`, `AMBIGUOUS`, `OUT_OF_SCOPE`, or `NOT_ASSESSED`.
Each `VIOLATION` must cite a requirement-matrix identifier and preserve the
minimal reproducing input. Security impact is assessed separately and is never
inferred solely from a normative violation.

## 7. Primary and secondary estimands

Primary estimands:

1. **Preserving migration yield:** semantic `PASS` divided by all valid-source
   attempts.
2. **Conditional semantic preservation:** semantic `PASS` divided by completed
   imports.
3. **Silent degradation rate:** `DEGRADED_SILENT` divided by completed imports.
4. **False-reassurance rate:** basic WebAuthn assertion passes while one or more
   other applicable functional oracles fail, divided by completed imports.

Secondary estimands include rejection, visible degradation, rollback, partial
state, individual-oracle preservation, and route-specific results.

Percentages must always include numerator, denominator, and a credential-cluster
bootstrap 95% interval. Comparisons between routes sharing source credential and
final provider use paired outcomes; unmatched naive tests are prohibited.

## 8. Campaigns

### C1 — Confirmatory semantic campaign

- 256 valid credentials.
- 12 frozen routes.
- 3,072 attempts per environment/repetition.
- Two exact repetitions in the frozen primary environment.
- Execution order deterministically shuffled from the registered seed.

### C2 — Robustness campaign

Mutation families are missing required field, invalid base64url, malformed
PKCS#8, key mismatch, RP-ID change, credential-ID collision, unknown optional
member, unknown required enumeration, minor-version increase, and major-version
mismatch. These results are reported by mutation family and are not pooled with
C1 preservation percentages.

### C3 — Fault and idempotence campaign

Sixty-four credentials balanced across the eight strata are exercised against
three destination profiles at five registered failure points. This produces
960 failure sequences; each sequence includes a retry where the state permits
one. Failure points are after validation, after approval, after payload decode,
after provisional persistence, and immediately before commit.

## 9. Exclusions, retries, and missing data

- Cases are excluded only for a pre-recorded harness/infrastructure failure
  that occurs before provider behavior is observed.
- A case is not excluded because it fails an oracle or surprises the researcher.
- Automatic infrastructure retry is limited to one and both attempts remain in
  the raw event log.
- Provider-level retries occur only in C3 and are part of the measured sequence.
- Missing or unobservable outcomes are `NOT_EVALUABLE` or `UNKNOWN`, never
  imputed as pass or fail.
- Every exclusion is emitted into `exclusions.jsonl` with a reason code.

## 10. Reproducibility controls

- Registered corpus seed: `20260912`.
- Configuration, source commit, locks, browser, CDP schema, and result hashes
  are recorded in the run manifest.
- Raw events are append-only JSONL; derived CSV and figures are regenerated.
- The second exact run must reproduce all deterministic oracle outcomes.
- Divergent environmental outcomes trigger an investigation and are retained.

## 11. Claim rules

- “CXF conformant” requires all applicable CXF matrix requirements to pass.
- “Authentication preserved” requires a real browser-mediated assertion
  accepted by the original RP verifier, not only a signature unit test.
- “PRF preserved” requires browser-observed equality for registered salts.
- “Provider behavior” names only the exact implementation/version tested.
- “Vulnerability” requires security-impact analysis and, where applicable,
  coordinated disclosure; difference, degradation, and violation are not
  synonyms for vulnerability.
- “First” or “novel” claims require a separately documented literature review.

## 12. Deviations

Changes after freeze require an entry in `docs/PROTOCOL_DEVIATIONS.md` containing
date, rationale, affected hypotheses/estimands, whether data had been inspected,
and the approving commit. Post-freeze changes create a new protocol version when
they alter an RQ, primary estimand, corpus, route, oracle, or classification.

