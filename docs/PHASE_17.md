# Phase 17: independent software PRF continuity through CXF

Status: source-informed exploratory addendum on 2026-10-02. The design was
written after a probe succeeded. It is outside the frozen v2.0 denominator and
is not a browser or mobile-provider migration.

## External implementation

The adapter runs Proton Pass's published `@protontech/pass-rust-core` 2.0.0
worker WASM package, pinned by `interop/proton-cxf-prf/package-lock.json`.
The corresponding open source tag resolves to commit
`69a0927f0fe7071243d6c38e404459a69210fdd4`. Code inspection found
CXF import/export mappings for both `credWithUV` and `credWithoutUV` and a
software WebAuthn authenticator. The package version and source tag match;
we did not reproduce the upstream binary build, so binary provenance beyond
the npm lockfile integrity is not independently established.

## Executed route and controls

Two deterministic synthetic ES256 passkeys without additional FIDO2 extensions,
each with distinct 32-byte HMAC seeds, crossed Proton's CXF importer, software authenticator, CXF exporter,
and a fresh import. Each repetition used two different PRF salts and a unique
challenge for every source/destination assertion. The Python driver checked
the exported passkey's credential ID, RP ID, user handle, PKCS#8 key and both
HMAC seed bytes against the original CXF document. It independently verified
each WebAuthn signature, challenge, origin, RP hash, UP/UV flags, and PRF
output against `HMAC-SHA-256(seedWithUV, SHA-256("WebAuthn PRF\0" || salt))`.
Proton also emits a basic-auth credential for the login, so the local
passkey-only validator checked a passkey projection while Proton reimported
the complete document.

A separate control changed only the `credWithUV` seed. It retained a valid
signing key and identity while the calculated and observed PRF changed. The
adapter returns raw synthetic evidence to the driver in memory. The saved
report includes public assertion transcripts, digests, counts and booleans,
but no CXF plaintext, signing keys, HMAC seeds or raw PRF outputs.

## Observations

| Oracle | Result |
|---|---|
| CXF import/export/reimport warnings | None in 2/2 repetitions |
| ID, RP, handle, key and both HMAC seeds | Equal in 2/2 repetitions |
| Positive signed assertions and separate UV PRF seed checks | 8/8 each verified |
| Changed-seed control signed assertions and separate PRF seed checks | 4/4 each verified; PRF changed in 2/2 |
| Same-salt source/destination PRF | Equal on both salts in 2/2 repetitions |
| Different-salt PRF | Different in 2/2 repetitions |
| Verifier rejects a changed signature | 2/2 repetitions |
| Verifier rejects a changed PRF output | 2/2 repetitions |

Total: 12/12 independent signature checks and 12/12 separate PRF seed checks,
including the changed-seed controls. The public result is
`experiments/phase17_exploratory/proton_cxf_prf.json`.
`./research.ps1 phase17-verify` independently recomputes the 12 signatures
and the 12 PRF digests from that retained report and the deterministic
synthetic fixture labels. The verifier has mutation tests for the signature
and PRF digest. It can verify these public observations, but the retained
report alone cannot prove the CXF bytes Proton handled or its internal state;
that requires rerunning Phase 17.

The PRF extension result is outside the bytes covered by the WebAuthn
signature. Signature verification and independent HMAC comparison are two
separate checks of observations returned by the same software call; they do
not make the PRF output cryptographically signed.
The last two rows are post-run checks of the independent verifier, not
additional provider robustness results. Its acceptance checks use explicit
exceptions and were also executed under Python optimized mode.

## Claim boundary

This is a positive *software authenticator* demonstration that an external
implementation can preserve the original CXF HMAC state and produce its UV
PRF after CXF reimport. It does not establish browser-to-browser continuity,
Android transfer, provider app storage, or two-provider CXP interoperability.
The `credWithoutUV` bytes survived CXF round trip, but a no-UV PRF ceremony
was not part of the recorded run. No positive no-UV behavioral claim follows.

The same Proton source tree contains CXP import/export handlers, but its
2.0.0 worker WASM package exposes CXF functions and no CXP handler. Source
inspection shows that Proton's CXP handler encrypts a CXF JSON document
directly with HPKE; this does not demonstrate the ZIP/JWE payload of the
public 2024 CXP Working Draft.

## Reproduce

From a PowerShell checkout with Node.js 24 and the project virtualenv:

```powershell
./research.ps1 phase17
./research.ps1 phase17-verify
```

The first command installs the pinned npm package, executes two synthetic
repetitions and changed-seed controls, and writes a new sanitized report
under `datasets/generated/phase17/`. The second verifies the tracked report
without installing the package.

Primary source: https://github.com/protonpass/proton-pass-common/tree/69a0927f0fe7071243d6c38e404459a69210fdd4
