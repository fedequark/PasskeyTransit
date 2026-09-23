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

Protocol v1.5 generates a fresh operating-system 32-byte nonce for every
ceremony and derives the primary signed challenge from a domain-separated canonical
context containing the attempt, credential hash, route, repetition, run,
source SPKI hash, source user-handle hash, RP ID and origin. The release gate
reconstructs the challenge, compares the context with the row, reproduces the
artifact hashes and rejects key substitution, reassignment or challenge reuse.
A second assertion uses another fresh nonce and signs a challenge committing to
the primary challenge plus the canonical retained extension observations. This
prevents coordinated rewriting of `largeBlob`, oracle status and unkeyed hashes.

PRF/HMAC and `credBlob` positive preservation remain `NOT_EVALUABLE` because
the Chromium CDP credential-import operation cannot inject their CXF state.
Missing required material is still a definite representation-level `FAIL`, but
it is not counted as browser-executed behavior. Secure Payment Confirmation
behavior is not exercised. Expected and observed `largeBlob` values are retained
so the release auditor can reproduce that browser oracle.

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

## Historical runs

Protocol v1.3 bound the row context but left the source SPKI and RP expectations
self-declared inside the retained transcript. Its arithmetic remains historical,
but v1.4 supersedes its independent key-continuity evidence. Protocol v1.5
supersedes v1.4 for extension-observation integrity.

Protocol v1.2 introduced unique challenges but did not cryptographically bind
the row context into the signed challenge and mixed nonexecuted representation
checks into its behavioral estimand. Its evidence is superseded by v1.3 and v1.4.

Protocol v1.1 corrected strict-profile behavior but reused one deterministic
challenge across C1 ceremonies. Its evidence is superseded by v1.2, v1.3 and v1.4 and must not
be presented as a standards-conforming relying-party ceremony campaign.

### v1.0 full run superseded by protocol v1.1

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
