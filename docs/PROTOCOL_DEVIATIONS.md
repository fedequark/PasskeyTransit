# Protocol deviations

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
