# PasskeyTransit research

This repository consolidates the research on semantic property preservation in
passkey migration through CXF/CXP.

## Public records

- Spanish replication package and manuscript:
  https://doi.org/10.5281/zenodo.22925150
- English manuscript translation:
  https://doi.org/10.5281/zenodo.22925334

The Zenodo records are linked reciprocally as original and variant forms. The
English translation reuses the evidence in the Spanish replication package and
does not introduce a second experimental dataset.

## Current status

The conceptual model and a simulated paper predate this repository. A later
conversation reported an MVP v0.1, but its source code and generated dataset
could not be recovered from accessible local storage. The implementation here
is therefore a clean, independently verifiable baseline reconstructed from the
reported requirements.

The baseline currently provides:

- deterministic synthetic ES256 credentials;
- an explicitly non-conformant experimental CXF subset representation;
- strict, permissive, and legacy reference-provider policies;
- direct and multihop migration routes;
- identity, key, signature, PRF-control, and `largeBlob` oracles;
- a deterministic 100-credential/8-route pilot producing 800 observations.

Phase 2 additionally provides a standards-aligned CXF passkey profile covering
the normative `Header → Account → Item → Passkey` envelope and passkey FIDO2
extensions. Its 29-requirement matrix distinguishes automated checks from
requirements that need a real WebAuthn or provider-behavior oracle.

It does **not** claim complete support for every CXF credential type or any
commercial provider. Phase 3 implements a
real browser-mediated WebAuthn ceremony using Chromium virtual authenticators,
including independent RP signature verification and `largeBlob` retrieval.
The public CDP import interface cannot inject CXF PRF/HMAC seed material, so PRF
preservation remains explicitly unevaluated. Phase 4 adds a real RFC 9180 HPKE
reference transport for the CXP Working Draft's core request/response fields.
Because that draft omits fields needed for challenge signatures and HPKE
encapsulation and underspecifies its ZIP/JWE payload, the missing pieces use a
clearly named experimental binding and normative interoperability is not
claimed. Phase 5 operationalizes the complete registered C1 shape as a
6,144-attempt synthetic reference-policy control campaign with structured
oracle states, exact designed-census summaries, and hashed artifacts. It is harness
qualification, not commercial-provider evidence. Phase 6 adds the frozen C2
robustness matrix and all 960 C3 fault/retry
sequences, including deliberate positive controls for simulated atomicity and
idempotence in an in-memory state machine. These remain synthetic RQ4 harness
evidence and do not establish durable-storage or crash-recovery behavior. Phase 7 adds
browser-backed WebAuthn evidence to C1, including UV, independent
assertion verification, zero-counter behavior, and `largeBlob`. Phase 8 checks
HPKE in both directions against the native `cryptography` implementation,
validates CXF with an independent Node.js consumer, and records a separate
ML-KEM-768+X25519 exploratory round trip. The legacy `cxf_subset` module
exists only to preserve the reconstructed Phase 0 pilot. Phase 9 derives a
hash-verified results package and current manuscript whose allowed and
prohibited claims are machine-readable.
Phase 10 adds a clean-tree, privacy-audited replication archive with two-level
hash verification. Phase 11 runs the pinned Bitwarden CXF Rust crate through a
stable external adapter. Phase 12 records an executable disposition for every
remaining oracle, and Phase 13 adds the focused literature review and
publication package. Protocol v1.5 additionally uses a second signed WebAuthn
ceremony to bind retained extension observations to the source-bound primary
assertion, verifies raw evidence through summaries and publication outputs,
and publishes all 96 exact route-by-stratum groups. Aggregate percentages are
design-weighted descriptions of the synthetic matrix. None of
these additions converts parser interop or
synthetic controls into commercial-provider evidence.

## Quick start

From PowerShell:

```powershell
./research.ps1 setup
./research.ps1 test
./research.ps1 protocol
./research.ps1 requirements
./research.ps1 cxp-requirements
./research.ps1 webauthn
./research.ps1 cxp
./research.ps1 campaign-c1
./research.ps1 phase6
./research.ps1 phase7
./research.ps1 phase8
./research.ps1 phase9
./research.ps1 phase11
./research.ps1 phase12
./research.ps1 phase13
./research.ps1 phase10
./research.ps1 verify-release
./research.ps1 pilot
```

The pilot writes generated artifacts under `datasets/generated/`. These files
are intentionally ignored by Git because they must be reproducible from source
and a recorded seed.

## Repository map

- `src/passkeytransit/`: executable research harness.
- `spec/`: versioned normative requirement matrices for the tested profile.
- `tests/`: baseline verification.
- `experiments/`: versioned experiment configurations.
- `datasets/`: generated datasets and future immutable releases.
- `paper/legacy/`: explicitly simulated legacy paper and rendered versions.
- `paper/current/MANUSCRIPT.md`: current Spanish manuscript.
- `paper/current/MANUSCRIPT_EN.md`: reviewed English translation.
- `docs/`: research state, provenance, and decision records.

The historical Phase 1 design is in `docs/EXPERIMENT_PROTOCOL.md`. The current
corrective design is in `docs/EXPERIMENT_PROTOCOL_V1_5.md`, with its
machine-readable counterpart in `experiments/protocol_v1.5.json`. It records
that prior data and reviews were inspected before the v1.5 corrections.

## Evidence policy

Only outputs generated by versioned code and accompanied by a run manifest are
empirical results. Numbers in `paper/legacy/` are simulated narrative examples
and must never be cited as experimental observations.
