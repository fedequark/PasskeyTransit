# Phase 12 remaining oracle disposition

Phase 12 converts every unclosed oracle into a machine-readable capability
decision in `paper/current/oracle_capabilities.json`. Positive behavioral claims
are allowed only for capabilities marked `EXECUTED`.

WebAuthn assertion, UV and `largeBlob` have browser-backed paths. PRF with and
without UV and positive `credBlob` preservation remain blocked because CDP
cannot inject their CXF state into a virtual authenticator. The next admissible
path is a native credential-provider test adapter or a software CTAP authenticator
whose import state is independently observable.

The payments member is format-tested but Secure Payment Confirmation remains
unevaluated because the lab lacks a payment-instrument enrollment and SPC RP
flow. The exploratory ML-KEM hybrid remains outside CXP v0. It cannot enter an
estimand until a separate profile fixes identifiers, encoding, transcript
binding, downgrade handling and test vectors.

These are closed dispositions, not positive results: each gap has an explicit
status, blocker, admissible next path and effect on claims.
