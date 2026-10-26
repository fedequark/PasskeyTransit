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
| V2-09 | Proton Pass software preserved original CXF HMAC seeds and UV PRF through its own import/export/reimport path | Pinned external WASM, both seed bytes, signed software WebAuthn assertions, separate HMAC oracle and changed-seed control | PASS in 2/2 selected exploratory runs; 8 positive signatures and PRF checks plus 4 changed-seed control signatures and PRF checks |
| V2-10 | A pinned open exporter produced a decryptable synthetic CXP-shaped ZIP/JWE passkey payload | `cxporter` original ZIP, project importer decryption, identity/HMAC comparison, wrong-recipient and ciphertext controls, signed software assertions | PASS in 2/2 selected runs; 8 signatures and 8 PRF bindings; response omits draft-required `archive` |
| V2-11 | A second open experimental importer accepted the `cxporter` response and payload | Its own positive import, full response parse, then isolated payload import using its recipient key | FAIL in 2/2: missing `archive` rejected by response parser; after bypassing that parser, JWE `alg` rejected before CXF recovery |
| V2-12 | A later index-layout boundary is reachable after using the second importer's own crypto envelope | Decrypt the retained synthetic `cxporter` index, positively self-import an unchanged PoC archive, replace only its index plaintext under the PoC's JWE profile, then call its unchanged importer | Local transformed control rejected `{accounts, …}` index for missing `{header, documents}`; this is not an import attempt on the original `cxporter` ZIP |

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
V2-09 is a software authenticator result, not a browser or provider-app
migration. Its no-UV seed bytes survived but no no-UV PRF ceremony was
evaluated. The PRF extension result itself is not covered by the WebAuthn
signature; the HMAC checks are independent. The retained synthetic public
transcripts permit independent recomputation of all 12 signatures and PRF
digests. Post-run verifier controls rejected two changed signatures and two
changed PRF outputs. See `PHASE_17.md`.
V2-10 and V2-11 use two independently maintained open codebases but not
installed provider apps. The selected second implementation is itself a
research PoC; its self-import positive control is not evidence that its
profile is the normative one. V2-11 isolates two rejection stages and
supports a specific incompatibility finding, while V2-05 remains
NOT_EVALUABLE for a successful two-provider CXP exchange. The local and
clean-CI reports are in `experiments/cxporter_cxp_open/`; the original CI
report ZIPs and executable adapters are retained. Two repetitions are
repeatability checks, not reliability or prevalence estimates.
The decrypted `cxporter` index also lacks the `{header, documents}` shape
expected by the selected PoC importer. This is a further source-and-plaintext
compatibility gap behind the observed schema/JWE failures. V2-12 now executes
that branch in an adapter-built envelope, but it is not a separately executed
rejection of the original ciphertext.
