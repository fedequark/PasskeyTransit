# Phase 2 — CXF passkey profile

## Scope

This phase implements and tests the CXF structures needed to exchange passkeys:
`Header → Account → Item → Passkey`, including the passkey FIDO2 extension
dictionary. It does not claim support for every non-passkey credential type in
CXF 1.0.

## Deliverables

- Normative requirement matrix tied to the 2026-03-09 errata baseline.
- Normative JSON field names and enclosing structures.
- PKCS#8 DER validation.
- Base64url and entity-identifier validation.
- HMAC credential UV/non-UV representation.
- Raw-DEFLATE `largeBlob` representation and size validation.
- `credBlob` and payments marker validation.
- Unknown-field and future-minor handling.
- Requirement coverage audit command.
- Positive and negative regression cases.

## Exit criteria

- [x] Passkey-profile normative matrix created.
- [x] Every automated requirement references at least one test.
- [x] Normative passkey document builder implemented.
- [x] Validator emits stable requirement IDs and paths.
- [x] Known-field importer ignores unknown optional members.
- [x] HMAC and large-blob structures implemented.
- [x] Requirement matrix audit executed successfully.
- [x] Full regression suite executed successfully.
- [x] Legacy pilot hash rechecked to prove Phase 0 isolation.

## Verification result

- Requirement profile: 29 requirements (`26 MUST`, `1 MUST NOT`, `2 SHOULD`).
- Automated total/profile/partial coverage: 21 requirements.
- Deferred to external or provider behavior: 8 requirements.
- Regression suite: `27 passed`.
- Phase 0 pilot result SHA-256 remains
  `5001abe2a0535ce584478fb353ae987270359f745c0c21b6db5c6a015e56a6d0`.

## Remaining non-Phase-2 obligations

Requirements involving a real WebAuthn assertion, imported signature-counter
behavior, and actual provider persistence remain assigned to Phase 3. Provider
UI editability and opaque commercial storage cannot be established by parsing a
CXF document.
