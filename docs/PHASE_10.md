# Phase 10 reproducible release

## Objective

Publish PasskeyTransit v0.5 as a hash-verifiable replication package generated
from a clean source commit.

## Release gate

The release command refuses a dirty Git tree, audits JSON and JSONL field names
for obvious secret-bearing fields, includes the tracked source snapshot and the
definitive Phase 6 to 12 evidence, and writes a deterministic ZIP. The external
manifest records the archive hash; the internal manifest records every entry
hash. `./research.ps1 verify-release` checks both layers.

The raw browser and fault records contain synthetic identifiers, statuses and
evidence hashes. They do not contain private keys or personal data. The release
retains them because they are necessary to reproduce denominators and paired
comparisons.

## Procedure

1. Create a fresh checkout at the release candidate commit.
2. Install the locked Python dependencies.
3. Run tests and validate the frozen protocol and requirement matrices.
4. Regenerate Phases 6, 7, 8, 11, 12 and 9.
5. Build and visually verify the manuscript artifacts.
6. Run `./research.ps1 phase10` and `./research.ps1 verify-release`.
7. Commit the immutable package and create the local annotated tag `v0.5.0`.

No command in this procedure publishes to a remote or creates a provider claim.
