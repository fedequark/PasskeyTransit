# Phase 6 — C2 robustness and C3 recovery controls

## Outcome

Phase 6 operationalizes the two frozen RQ4 campaigns that were still missing.
Both use synthetic, versioned control implementations and therefore qualify
the harness without making claims about commercial providers.

## C2 — robustness

C2 applies each of the ten registered mutation families to one deterministic
representative of every feature stratum, producing 80 attempts:

- missing required member;
- invalid base64url;
- malformed PKCS#8;
- private/public-key mismatch;
- RP-ID change;
- credential-ID collision;
- unknown optional member;
- unknown required enumeration;
- minor-version increase;
- major-version mismatch.

Results are reported separately by family and are never pooled into a
preservation percentage. Invalid documents are rejected before persistence.
Valid but semantically changed documents exercise the independent identity and
key oracles. Each record contains a deterministic mutation recipe and a digest
of the minimal reproducer; secret key material is not written.

## C3 — fault injection, rollback and retry

C3 selects the registered 64 credentials—eight per stratum—and crosses them
with three destination controls and five failure points. The result is exactly
960 fault sequences and 1,920 event records covering initial failure and retry.

The `strict` and `compatible-lossy` stores roll back provisional writes at all
failure points. The deliberately defective `legacy` control retains an
uncommitted copy after `after-provisional-persistence` and `before-commit`;
retry then creates a second copy. This provides a known positive control for
the atomicity and idempotence oracles.

State snapshots contain counts and SHA-256 references only. Credential
plaintext and private material remain ephemeral.

## Reproduction

```powershell
./research.ps1 test
./research.ps1 phase6
```

Every invocation creates a new timestamped directory under
`datasets/generated/phase6/`. Files are created exclusively and prior evidence
cannot be overwritten.

## Exit criteria

- [x] Ten frozen C2 mutation families executed across eight strata.
- [x] C2 results kept separate by mutation family.
- [x] Minimal cases reproducible without persisting secrets.
- [x] Exactly 960 C3 failure sequences executed.
- [x] Initial and retry events retained separately.
- [x] State captured before failure, after failure and after retry.
- [x] Atomicity and idempotence positive controls detected.
- [x] Artifacts and protocol inputs hashed in run manifests.
- [x] Evidence boundary prohibits provider claims.
