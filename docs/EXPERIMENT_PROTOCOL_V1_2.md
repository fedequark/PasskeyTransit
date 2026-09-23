# PasskeyTransit experimental protocol v1.2

Status: **frozen before the v0.4 corrective replication**

Freeze date: 2026-09-23

Protocol ID: `passkeytransit-semantic-preservation-v1.2`

## Purpose of this revision

Protocol v1.2 supersedes v1.1 for new evidence. Data from v1.1 had been
inspected before this correction. The new campaign is therefore described as a
corrective replication under a post-inspection revised protocol, not as an
independent preregistered confirmation.

The revision retains the corpus, routes, provider controls, strict rejection
rule, mutation families, fault points and registered deterministic seed. It
changes the WebAuthn challenge policy and makes the false-reassurance estimand
unambiguous.

## WebAuthn challenge and transcript binding

The relying-party harness generates a fresh 32-byte value with the operating
system cryptographic random generator for every registration or authentication
ceremony. No challenge may be reused within a release. The assertion signs the
challenge through `clientDataJSON`; the retained transcript records the expected
challenge and expected `attempt_id`.

The release auditor must verify signature, origin, RP-ID hash, flags, counter,
credential ID, user handle, transcript commitment, equality between the row and
transcript attempt identifiers, a minimum challenge length of 16 bytes, and
global challenge uniqueness across every retained C1 calibration and full-run
transcript.

Random challenges intentionally make raw signatures non-deterministic. Exact
repetitions apply to registered semantic outcomes, not byte identity.

## False reassurance and the payments marker

The primary false-reassurance estimand is a successful WebAuthn assertion with
at least one failed **browser-executable behavioral oracle**, divided by
successful assertions. Its registered behavioral set is `uv`, `prf_uv`,
`prf_no_uv`, `large_blob`, and `cred_blob`.

`payments_marker` is excluded from that primary estimand because this harness
observes only CXF field retention and does not execute Secure Payment
Confirmation. It remains part of semantic format preservation. A separate
sensitivity estimand, `login_with_any_observed_property_failure_rate`, adds the
format-only payments marker to the behavioral set. Both numerator and
denominator must be published together.

## Preserved design and claim boundary

C1 contains 3,072 designed synthetic credential×route cells, each executed
twice. C2 contains 80 mutation cases and C3 contains 960 fault sequences. The
cluster-bootstrap intervals remain descriptive sensitivity summaries rather
than population confidence intervals.

The four provider labels remain instrumented controls rather than commercial
products. PRF and positive `credBlob` preservation remain non-evaluable through
CDP. The CXP binding and hybrid PQC experiment remain explicitly experimental.

## Release gate

A v1.2 release is admissible only when all campaign and interoperability inputs
name one clean tracked source commit, all 6,144 C1 rows are present, semantic
repetitions agree, every imported transcript has a unique sufficiently long
challenge bound to its row, primary and sensitivity estimands are both emitted,
all hashes verify, and the release contains exactly one canonical analysis
manifest.
