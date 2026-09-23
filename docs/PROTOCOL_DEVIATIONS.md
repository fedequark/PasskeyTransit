# Protocol deviations

## 2026-09-23 signed-extension, derivation, and scope correction

Date: 2026-09-23

Commit: recorded by SHA-256 in each v0.7 campaign manifest

Data inspected before decision: yes

Reason: the v1.4 signature bound the primary assertion to source context, but
the retained extension response and its oracle were protected only by unkeyed
hashes. A coordinated rewrite could therefore preserve a valid primary
signature. The release verifier also checked stored hashes without deriving
summaries and publication outputs from raw records. Finally, C3 used a Python
list but its claim matrix described durable state.

Affected RQs: RQ1, RQ2, RQ3 and RQ4

Affected estimands: evidentiary integrity of browser extension outcomes,
reproducibility of all reported results, interpretation of aggregate C1
percentages, and scope of the C3 fault controls

Change: protocol v1.5 adds a second signed WebAuthn challenge committing to the
primary challenge and canonical extension observations; recomputes C1/C2/C3
summaries and managed publication outputs during release verification; labels
aggregate percentages as design-weighted; and reclassifies C3 as an in-memory,
non-durable simulation.

Impact on interpretation: v1.4 arithmetic remains historical, but v1.5
supersedes its extension-integrity and release-reproducibility claims. No C3
result supports durable-storage or process-crash recovery behavior.

## 2026-09-23 source-key binding and exact-design correction

Date: 2026-09-23

Commit: recorded by SHA-256 in each v0.6 campaign manifest

Data inspected before decision: yes

Reason: the v1.3 public verifier checked an ES256 signature against an SPKI
stored inside the same transcript but did not bind that SPKI to the source-key
oracle. A replacement key and freshly generated signature could therefore pass
after recomputing unkeyed commitments. Its credential-cluster bootstrap also
randomly reweighted deliberately balanced feature strata despite zero outcome
variation inside every route-by-stratum cell.

Affected RQs: RQ1, RQ2 and RQ3

Affected estimands: evidentiary strength of key continuity and presentation of
all C1 proportions

Change: protocol v1.4 signs source SPKI hash, source user-handle hash, RP ID and
origin as part of the attempt binding; reproduces all retained artifact hashes;
adds key-substitution regression tests; and reports exact designed-census
proportions plus the complete 96-cell route-by-stratum matrix without sampling
intervals.

Impact on interpretation: v1.3 arithmetic remains reproducible, but v1.4
supersedes its claim of independently source-bound public browser transcripts.
The v1.4 campaign is another post-inspection corrective replication.

## 2026-09-23 capability classification and signed row binding correction

Date: 2026-09-23

Commit: recorded by SHA-256 in each v0.5 campaign manifest

Data inspected before decision: yes

Reason: v1.2 mislabeled PRF and `credBlob` representation checks as
browser-executable behavioral oracles. Its retained challenge was unique and
signed, but the attempt identifier was only a mutable transcript field. A valid
transcript could therefore be reassigned to another row after recomputing the
unkeyed transcript hash. The retained evidence also did not permit the release
auditor to reproduce the `largeBlob` oracle.

Affected RQs: RQ1, RQ2 and RQ3

Affected estimands: behavioral false reassurance, representation-loss
sensitivity and the evidentiary strength of C1 transcript-to-row attribution

Change: protocol v1.3 limits the primary behavioral set to `uv` and
`large_blob`; reports nonexecuted representation loss and payment-marker loss
separately; derives the signed challenge from a fresh nonce and canonical row
context; checks credential hash against the row; and retains expected and
observed `largeBlob` values for independent oracle reconstruction.

Impact on interpretation: v1.2 remains historical and its arithmetic remains
reproducible, but its 40% value must not be described as fully browser-executed
behavior. The v1.3 run is a post-inspection corrective replication.

## 2026-09-23 WebAuthn challenge and estimand correction

Date: 2026-09-23

Commit: recorded by SHA-256 in each v0.4 campaign manifest

Data inspected before decision: yes

Reason: v1.1 reused one deterministic WebAuthn challenge across ceremonies,
contrary to the relying-party challenge requirements in WebAuthn Level 3. The
registered false-reassurance wording also did not explicitly distinguish
browser-executable behavioral oracles from the format-only payments marker.

Affected RQs: RQ1, RQ2 and RQ3

Affected estimands: false reassurance and the evidentiary strength of the C1
WebAuthn ceremony

Change: protocol v1.2 requires a fresh cryptographically random 32-byte
challenge per ceremony, challenge uniqueness auditing, and transcript binding
to the attempt identifier. The primary false-reassurance estimand now names its
five behavioral oracles; a separate sensitivity estimand includes the payments
marker.

Impact on interpretation: v1.1 C1 evidence remains historical and is
superseded. The v1.2 run is a corrective replication under a post-inspection
revised protocol, not an independent preregistered confirmation.

## 2026-09-23 strict-profile correction

Date: 2026-09-23

Commit: recorded by SHA-256 in each corrected v0.3 campaign manifest

Data inspected before decision: yes

Reason: the v1.0 implementation treated the `strict` destination as a
lossless pass-through even when a prior hop had already discarded a required
source property. This contradicted the frozen provider definition.

Affected RQs: RQ1, RQ2 and RQ3

Affected estimands: preserving migration yield, conditional semantic
preservation, silent degradation, false reassurance and paired route outcomes

Change: protocol v1.1 requires rejection before persistence and browser
ceremony when the candidate no longer contains an applicable required source
property. It also retains auditable WebAuthn transcripts and clarifies that
bootstrap intervals are descriptive sensitivity analyses.

Impact on confirmatory interpretation: the historical v1.0 C1 run is
superseded. Its 6,144-import denominator and derived C1 percentages must not be
cited as v1.1 results. C2, C3 and interoperability evidence are rerun so the new
release has one source commit and one protocol identifier.

Use this template for every post-freeze deviation:

```text
Date:
Commit:
Data inspected before decision: yes/no
Reason:
Affected RQs:
Affected estimands:
Change:
Impact on confirmatory interpretation:
```
