# Claim-to-measurement matrix

This matrix defines the minimum evidence needed for paper claims. Claim IDs are
stable across protocol-compatible revisions.

| ID | Planned claim | Required measurement | Denominator | RQ | Status |
|---|---|---|---|---|---|
| CLM-01 | Direct migration preserves or changes cryptographic identity | `credential_id`, `rp_id`, `user_handle`, `public_key`, and browser assertion oracles | All valid direct attempts | RQ1 | Confirmatory |
| CLM-02 | Basic authentication can miss functional loss | Assertion `PASS` paired with any applicable PRF/blob/UV `FAIL` | Completed imports with assertion `PASS` | RQ2 | Confirmatory |
| CLM-03 | PRF behavior is preserved or changed | Browser-observed PRF outputs for registered salts and UV modes | Completed applicable PRF imports | RQ2 | Confirmatory |
| CLM-04 | Blob semantics are preserved or changed | Ground-truth byte equality after browser write/read behavior | Completed applicable blob imports | RQ2 | Confirmatory |
| CLM-05 | Migration outcome depends on path | Matched credential/final-provider outcomes across direct and multihop routes | Registered matched route pairs | RQ3 | Confirmatory |
| CLM-06 | Unknown/versioned data causes reject, preservation, or degradation | Execution and semantic axes by registered mutation family | All robustness cases | RQ4 | Confirmatory |
| CLM-07 | Import is or is not idempotent | Final credential count and semantic state after repeated import | All registered retry sequences | RQ4 | Confirmatory |
| CLM-08 | Failure handling is atomic or recoverable | Durable state before failure, after failure, and after retry | All fault sequences | RQ4 | Confirmatory |
| CLM-09 | A behavior violates CXF/CXP | Minimal case plus applicable requirement-matrix ID | Cases assessed against that requirement | RQ1–RQ4 | Normative |
| CLM-10 | Migration changes the instrumented clone set | Ground-truth provider copy-set delta | Synthetic instrumented cases only | Exploratory | Exploratory |

Prohibited substitutions:

- Parser acceptance cannot substitute for CXF conformance.
- Direct cryptographic signing cannot substitute for a WebAuthn ceremony.
- Preservation in a reference profile cannot substitute for vendor evidence.
- A simulated or deliberately lossy control cannot be counted as a discovered
  implementation defect.

