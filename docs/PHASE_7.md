# Phase 7 — browser-backed C1 control campaign

## Outcome

Phase 7 connects the registered C1 route engine to real WebAuthn assertions in
Chromium. Each migrated CXF passkey is injected into a fresh logical slot of a
virtual authenticator, exercised through `navigator.credentials.get()`, and
removed before the next attempt.

The local RP preserves the five deterministic RP IDs from the frozen corpus.
Chromium host-resolution and secure-origin test flags route these names to an
ephemeral loopback HTTP server. Five isolated page/CDP surfaces avoid changing
the registered deterministic execution order.

## Observed browser oracles

The runner verifies independently in Python:

- credential ID and user handle;
- challenge, origin and WebAuthn ceremony type;
- RP-ID hash;
- user-presence and user-verification flags;
- ES256 assertion signature against the source public key;
- CXF-required zero signature-counter behavior;
- browser-returned `largeBlob` bytes.

PRF/HMAC and `credBlob` positive preservation remain `NOT_EVALUABLE` because
the Chromium CDP credential-import operation cannot inject their CXF state.
Missing required material is still a definite `FAIL`. Secure Payment
Confirmation behavior is not exercised.

## Execution gates

`./research.ps1 phase7` first runs a 96-attempt calibration containing one
credential from every stratum across all routes. The complete 6,144-attempt
campaign starts only if every calibration WebAuthn assertion passes. Both runs
use immutable timestamped artifact directories and record the browser binary
hash, browser version, Playwright version, source commit and protocol hash.

This remains a reference-policy/virtual-authenticator control. It supplies
real browser evidence but does not authorize claims about commercial providers.
