# Phase 5 — registered C1 campaign machinery

## Outcome

Phase 5 operationalizes the frozen C1 design as a reference-policy control
campaign. It generates the registered 256-credential corpus, balances 32
credentials in each of eight strata, executes all 12 routes twice, and emits
6,144 immutable attempt records.

This completes the executable scope registered as PasskeyTransit v0.2 and the
package version is advanced from the reconstructed v0.1 baseline to `0.2.0`.

Each hop passes the CXF document through the Phase 4 CXP/HPKE transport before
applying its destination control policy. The four policy labels are synthetic:

- `reference` and `strict` preserve the supported document;
- `compatible-lossy` removes HMAC credentials and `credBlob` only after a
  machine-readable pre-commit declaration;
- `legacy` silently removes all passkey extension material.

These policies are experimental stimuli, not observations of commercial
providers.

## Evidence model

Every JSONL attempt follows the Phase 1 data dictionary and contains all 15
registered oracle outcomes. Evidence references are SHA-256 digests; raw
private keys, HMAC material, blobs, credential plaintext, and account PII are
never written to the campaign artifacts.

The runner deliberately reports browser-dependent positive results as
`NOT_EVALUABLE`:

- `webauthn_assertion` and UV always require an observed WebAuthn ceremony;
- presence and byte equality of HMAC or blob material can prove obvious loss,
  but cannot establish positive PRF or browser blob preservation.

Consequently, this campaign qualifies the orchestration and classification
pipeline. It does not authorize confirmatory provider claims.

## Derived artifacts

`./research.ps1 campaign-c1` creates, under
`datasets/generated/phase5_c1/<run timestamp>/`:

- `c1_phase5_attempts.jsonl`: append-shaped raw attempt records;
- `c1_phase5_derived.csv`: regenerated flat oracle table;
- `c1_phase5_summary.json`: classifications and four registered estimands;
- `c1_phase5_manifest.json`: source/environment metadata and hashes.

Every run uses a fresh directory and exclusive file creation. Existing raw or
derived evidence is never overwritten.

Every percentage records numerator, denominator, point estimate, and a
credential-cluster bootstrap 95% interval. An estimand with no observable
denominator remains `null` rather than being imputed. Routes sharing a final
provider are compared only as matched credential/repetition pairs; the summary
reports semantic and oracle discordance without an unmatched significance
test.

## Exit criteria

- [x] Frozen 256 × 12 × 2 design executed.
- [x] Deterministic order derived from seed `20260912`.
- [x] Two repetitions produce equivalent deterministic oracle outcomes.
- [x] All 15 oracle keys and all three classification axes are emitted.
- [x] Cluster-aware intervals are generated.
- [x] Path comparisons use paired outcomes for common credentials.
- [x] Raw and derived artifacts are independently hashed.
- [x] Existing campaign evidence cannot be overwritten.
- [x] No secret credential material is persisted.
- [x] Evidence boundary prevents vendor or positive browser claims.
