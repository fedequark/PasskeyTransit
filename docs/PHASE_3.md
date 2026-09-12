# Phase 3 — Browser-mediated WebAuthn equivalence

## Scope

Register an ES256 discoverable credential in a Chromium virtual authenticator,
export it through the Phase 2 CXF passkey profile, import the CXF material into
a fresh virtual authenticator, and execute a browser-mediated WebAuthn assertion
verified against the original RP public key.

## Trust boundaries

- The local HTTP origin is a minimal RP test surface on `localhost`, which is a
  secure context for WebAuthn.
- Browser mediation is performed by Microsoft Edge/Chromium through Playwright
  and a CDP session.
- The RP verifier runs independently in Python and checks client data,
  RP-ID hash, UP/UV flags, credential identity, signature, and counter semantics.
- CXF is the only source used to construct the destination credential object.

## Oracles implemented

- Registration raw ID equals the credential captured from the authenticator.
- CXF profile validation succeeds.
- Imported private key derives the registration public key.
- Destination contains exactly one imported credential.
- Assertion credential ID and user handle match the source.
- Client challenge, origin, ceremony type, and RP-ID hash match.
- UP and UV flags are present.
- ES256 assertion signature verifies against the original RP public key.
- Imported assertion reports signature counter zero.
- `largeBlob` application bytes survive CXF DEFLATE and browser retrieval.

## Automation boundary discovered

The public CDP `WebAuthn.addCredential` interface accepts private key, identity,
counter, backup flags, and `largeBlob`, but it does not accept the CXF
`hmacCredentials` UV/non-UV seed material. CDP can advertise PRF capability,
but cannot recreate the source PRF secret during import. Consequently, this
phase reports PRF preservation as not evaluated instead of converting an
automation limitation into a semantic failure.

## Exit criteria

- [x] Minimal local RP surface implemented.
- [x] Chromium virtual authenticator registration implemented.
- [x] Registered credential exported through CXF.
- [x] CXF credential imported into a fresh authenticator.
- [x] Independent RP assertion verifier implemented.
- [x] `largeBlob` read after migration implemented.
- [x] Browser migration command executed successfully twice.
- [x] Full regression suite executed successfully.
- [x] Environment and evidence manifest reviewed.

## Verification result

- Browser: Microsoft Edge/Chromium `153.0.4234.32`.
- Automation: Playwright `1.62.0` plus the browser CDP WebAuthn domain.
- Browser migration: 15/15 checks passed in two consecutive executions.
- Repeated check maps: identical.
- Full repository suite: `28 passed`.
- Evidence output: `datasets/generated/webauthn_phase3_result.json`
  (generated and intentionally not versioned).
