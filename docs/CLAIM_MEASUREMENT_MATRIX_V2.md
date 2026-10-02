# v2 claim-to-measurement matrix

This is a follow-up to `CLAIM_MEASUREMENT_MATRIX.md`; it does not rewrite the
frozen v1.5 claim permissions.

| ID | Claim permitted by evidence | Required measurement | Current state |
|---|---|---|---|
| V2-01 | Fenko imported a synthetic CXF passkey and authenticated with it | UI import, retained identity, independent signed WebAuthn transcript | PASS in 2/2 runs |
| V2-02 | The destination PRF output diverged from the source CXF HMAC-seed control | Source standard software output, browser PRF result, repeated input, changed input, signed observation witness | FAIL against the seed control in 2/2 runs; source browser continuity not evaluated |
| V2-03 | Fenko retained these credentials after a process restart and skipped a duplicate | Pre/post storage counts and signed assertion after restart | PASS in 2/2 runs |
| V2-04 | Its export retained or omitted tested passkey fields | Export UI document, identity comparison, version and extension representation | IDs/handles retained; PRF extensions omitted; username changed; version 0.0 |
| V2-05 | Two independent providers completed the public CXP Working Draft wire exchange | Actual provider request/response, HPKE selection, ZIP/JWE payload and import receipt | NOT_EVALUABLE |
| V2-06 | The original CXF HMAC-seed PRF survived browser-to-browser migration | Same input, source and destination signed browser observations with restored HMAC state | NOT_EVALUABLE |
| V2-07 | Fenko's PRF output stayed equal across two Fenko browser profiles after its own CXF export/import | Source and destination signed browser observations, same fixed input, second input and PRF digest witnesses | PASS in 2/2 selected same-provider runs; original CXF seed state not preserved |
| V2-08 | Two distinct Android provider apps completed a platform-mediated CXF transfer | Separate synthetic vaults, app versions, system transfer receipt, imported identity and signed browser assertion | NOT_EVALUABLE |

The denominators for V2-01 through V2-04 are two designed repetitions of one
selected open provider route. They are repeatability checks, not independent
providers or a population sample. No prevalence, vendor-wide quality, or
Bitwarden behavior claim follows from these rows.
V2-07 is an exploratory source-informed addendum with two further
repetitions, not part of the v2.0 denominator. It does not satisfy V2-06,
which requires continuity of the original HMAC state.
V2-05 and V2-08 are distinct: Android's documented transfer API provides a
CXF JSON payload through a system-mediated Content URI; that observation
would not by itself establish the public Working Draft ZIP/JWE framing. See
`CXP_PROVIDER_FEASIBILITY_2026.md`.
