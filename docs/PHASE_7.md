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
campaign starts only if every imported calibration credential yields a valid
WebAuthn assertion; strict-profile rejections have no browser ceremony. Both runs
use immutable timestamped artifact directories and record the browser binary
hash, browser version, Playwright version, source commit and protocol hash.
The manifest also records the CDP protocol version, a hash of the exposed CDP
domain schema, the dependency lock hash, and the complete frozen specification
baseline.

The browser is discovered from `PASSKEYTRANSIT_BROWSER`, the executable search
path, or standard Chromium installation locations. The CLI also accepts an
explicit `--browser` path. PRF is requested during imported assertions, and
`prf_requested`/`prf_observed` are recorded; positive PRF preservation remains
unassessed because the import interface cannot restore the source HMAC secret.

This remains a reference-policy/virtual-authenticator control. It supplies
real browser evidence but does not authorize claims about commercial providers.

## Historical v1.0 full run superseded by protocol v1.1

The definitive run used Edge `153.0.4234.32`, CDP protocol `1.3`, Playwright
`1.62.0`, and clean source commit `d2893c3`. Results:

- 6,144/6,144 imports, WebAuthn assertions, and UV checks passed;
- 2,304 semantic `PASS`, 1,408 visible degradations, 1,920 silent
  degradations, and 512 `NOT_EVALUABLE`;
- 768/1,536 applicable `largeBlob` cases passed and 768 deliberately lossy
  routes failed;
- preserving yield: 2,304/6,144 = 37.50% (credential-bootstrap 95% interval
  32.42%–42.77%);
- false reassurance: 2,944/6,144 = 47.92% (43.36%–52.93%);
- both repetitions were deterministically equivalent.

These proportions describe the earlier control behavior and must not be cited
as results of the strict-profile revision.
