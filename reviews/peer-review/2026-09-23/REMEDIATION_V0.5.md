# PasskeyTransit v0.5 remediation record

Date: 2026-09-23

Reviewed source commit: `cc599feea4704b798e7cb3f37de326af1e5c4324`

## Scope

This record maps the findings from the preceding review cycle to the corrective
changes in protocol v1.3 and release v0.5.0. Historical v0.2, v0.3 and v0.4
artifacts remain unchanged.

## Finding resolution

### Browser capability classification

The earlier 40% false-reassurance result combined browser-executed failures
with representation losses that CDP cannot execute. Protocol v1.3 now limits
the primary browser-executed estimand to `uv` and `large_blob`. It reports PRF
and `credBlob` representation loss separately and preserves explicit union
estimands.

The regenerated full campaign reports:

| Quantity | Numerator | Denominator | Rate |
|---|---:|---:|---:|
| Browser-executed false reassurance | 512 | 5,120 | 10% |
| Login with nonexecuted representation loss | 1,792 | 5,120 | 35% |
| Login with any non-payment property failure | 2,048 | 5,120 | 40% |
| Login with any observed property failure | 2,304 | 5,120 | 45% |

The capability report lists WebAuthn assertion verification, UV and
`large_blob` as executed. PRF and `credBlob` remain blocked by the current CDP
interface, and the payments marker remains format-only.

### Transcript-to-row binding

Every browser ceremony now derives its signed challenge as
`SHA-256(domain || nonce || canonical_attempt_context)`. The context includes
protocol, campaign, run, attempt, credential hash, stratum, route, repetition
and provider chain. The independent verifier reconstructs the challenge,
compares the complete context with the enclosing row and checks that the
asserted credential ID hashes to the row credential hash.

An adversarial reassignment test changes the row context and recomputes the
unkeyed transcript hash. Verification rejects it because the original signed
challenge no longer commits to the modified context.

### Retained largeBlob evidence

Each imported row now retains applicability, expected bytes and browser-returned
bytes for `largeBlob`. The auditor derives applicability from the registered
feature stratum and recomputes the oracle status and evidence hashes. A tamper
test that changes the observed bytes and recomputes the unkeyed extension hash
is rejected.

### Claim and publication corrections

Protocol v1.3, the data dictionary, claim matrix, manuscript, results tables and
submission checklist now use the same capability boundary. The manuscript
labels the run as a post-inspection corrective replication and does not present
the result as independent preregistered confirmation. The DOCX and PDF builder
also prevents heading overlap, keeps the compact result table together, repeats
table headers when needed and keeps headings with following text.

## Verification

- 64 automated tests passed.
- The full browser campaign completed 6,144 attempts with equivalent repeats.
- The release auditor independently verified 5,200 imported transcripts across
  calibration and full runs, 5,200 unique challenges, 5,200 row bindings and
  5,200 `largeBlob` oracle evaluations.
- Release archive SHA-256:
  `a1811d2341d9094ee8dc202a062885f8a0ba2bb28f431b4bd8d6202d1c394ae9`.
- Privacy audit inspected 9,213 JSON records and found no sensitive field names.
- Every page of the final DOCX and PDF was rasterized and visually inspected.

