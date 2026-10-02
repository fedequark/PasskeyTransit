# Phase 14: cross-runtime exchange and executable PRF loss control

Status: exploratory feasibility evidence, generated after inspecting the v0.7.1
results. This phase is not part of the frozen v1.5 C1 estimands or the v0.7.1
replication archive. It must not be presented as an independent preregistered
confirmation.

## Cross-runtime exchange

`interop/node_cxp_exchange.mjs` implements the project's experimental
single-document CXP/HPKE binding independently of the Python code, using
Node.js crypto and zlib. The runner exchanges a synthetic CXF passkey in both
directions:

1. Node exporter to Python importer.
2. Python exporter to Node importer.
3. Node importer rejects a modified ciphertext.

Both recipients compare the recovered CXF document to the source. This is an
end-to-end exchange between two separately written implementations of the
*experimental binding*. The Node implementation was authored in this project;
it is not a third-party credential provider. CXP Working Draft ZIP/JWE framing,
exporter identity authentication, user authorization and durable provider
storage remain outside the tested profile. The pinned Bitwarden crate used in
Phase 11 provides CXF parsing and serialization, not those missing provider
behaviors.

The same exchange also executes the CXF `hmacCredentials` state with both UV
seeds. A separate Node evaluator and the Python runner compute the WebAuthn PRF
salt mapping and HMAC before and after transport; they agree for the preserved
state and reject a removed state. This is a positive **software functional
control**, not a browser or CTAP PRF ceremony.
The mapping follows WebAuthn Level 3 §10.1.4 and the CXF
`Fido2HmacCredentials` seed rule:

- https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#prf-extension
- https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html#fido2hmaccredentials

## Browser-executed PRF control

The browser creates a passkey with PRF enabled. Three signed WebAuthn assertions
establish that its PRF result exists, is stable for the same input and differs
for another input. The credential fields exposed by CDP are converted to CXF,
transported through the Node exporter and Python importer, and injected into a
new Chromium virtual authenticator. A fourth signed assertion proves basic
authentication still works and tests PRF with the original input.

The observed result is an intentional **loss control**: CDP exports the signing
key but does not expose or inject the PRF secret, so the destination PRF result
is absent. This detects a functional loss that CXF parsing and a successful
login cannot detect. It does not prove positive PRF preservation. The runner
records only a SHA-256 digest of the source PRF result, never the raw result or
private key. Its observation is local to Chromium virtual authenticators and
the tested CDP import path; it is not a finding about a commercial provider.

## Reproduce

With a working project virtual environment, Node.js and Edge/Chrome:

```powershell
./research.ps1 phase14
```

This writes immutable per-run JSON reports below
`datasets/generated/phase14/<timestamp>/`. Or invoke the CLI operations
`cross-runtime-cxp` and `prf-migration` separately. The code-level tests are
`tests/test_cross_runtime.py` and `tests/test_prf_migration.py`.

The first exploratory run is retained in
`experiments/phase14_exploratory/cross_runtime_cxp.json` and
`experiments/phase14_exploratory/prf_migration.json`; a second browser run is in
`experiments/phase14_exploratory/prf_migration_chrome.json`. The reports contain
implementation hashes and check results, but no private key or raw PRF output.
On the recorded run, both exchange directions, ciphertext-tamper rejection,
both software PRF modes and the missing-state control passed. Edge 154 returned
a stable source PRF value for a repeated input, a different value for a second
input, valid signed assertions before and after import, and no PRF result after
the CDP-based import. Chrome 154 reproduced the same check outcomes.

## What remains for a provider study

A third-party exporter and importer with passkey support, or a provider's
documented test interface, must perform the exchange and expose enough state
for the same identity, assertion and extension oracles. A positive PRF result
requires an import path that restores the authenticator's PRF state and returns
matching WebAuthn PRF outputs for the same input before and after migration.
The present CDP interface cannot supply that state.
