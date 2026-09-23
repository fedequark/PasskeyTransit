# Phase 9 — verified analysis and current manuscript

## Outcome

Phase 9 replaces the simulated legacy narrative with a new manuscript generated
only from Phase 6–8 artifacts. Before analysis, every C1/C2/C3 summary hash is
checked against its manifest and every source tree must have been clean. The
complete C1 run must contain 6,144 attempts and equivalent repetitions; C3
must contain 960 sequences; all applicable Phase 8 checks must pass.

The analysis emits:

- `results_v0.6.json`, preserving the complete evidence and claim boundary;
- five CSV tables for C1 estimands/oracles/route-stratum cells, C2 mutations and C3 faults;
- `MANUSCRIPT.md`, a non-simulated Spanish research manuscript;
- `analysis_manifest.json`, hashing every input and output.

## Claim boundary

The manuscript may conclude that the harness detects deliberately introduced
semantic, route, atomicity and idempotence losses, and that basic authentication
is insufficient in those controls. It may report bidirectional HPKE
interoperability with the identified native implementation.

It may not infer commercial-provider behavior, full normative CXP
interoperability, positive PRF/`credBlob` preservation, vulnerability,
prevalence, or novelty. These prohibitions are stored in the results artifact,
not left as editorial convention.

## Reproduction

```powershell
./research.ps1 phase9
```

The command selects the latest complete Phase 6, 7 and 8 runs, verifies their
hashes and source commit, and writes a timestamped, immutable candidate under
`datasets/generated/analysis/`.

## Verified package

The historical generated manuscript reports 6,144 browser-backed C1 attempts, 80 C2
robustness attempts, 960 C3 sequences/1,920 events, and the Phase 8 independent
boundary. `analysis_manifest.json` records every selected input hash and every
derived output hash, with `claim_boundary_enforced: true`.

The historical v0.2 files predate the strict-profile change. A
revision must be generated from new Phase 6–8 inputs into a new output
directory, and its release must resolve every analysis input/output hash.
