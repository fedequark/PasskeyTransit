# Claim-to-measurement matrix

This matrix defines the minimum evidence needed for paper claims. Claim IDs are
stable across protocol-compatible revisions.

| ID | Planned claim | Required measurement | Denominator | RQ | Status |
|---|---|---|---|---|---|
| CLM-01 | Direct migration preserves or changes cryptographic identity | `credential_id`, `rp_id`, `user_handle`, `public_key`, and row-bound browser assertion oracles | All valid direct attempts | RQ1 | Corrective control evidence |
| CLM-02 | Basic authentication can miss browser-executed functional loss | Assertion `PASS` paired only with applicable `uv` or `large_blob` `FAIL` | Completed imports with assertion `PASS` | RQ2 | Corrective control evidence |
| CLM-03 | PRF representation is retained or lost; positive PRF behavior remains untested | CXF representation equality; browser behavior is `NOT_EVALUABLE` | Completed applicable PRF imports | RQ2 | Representation only |
| CLM-04 | `largeBlob` behavior and `credBlob` representation are preserved or changed | Retained browser `largeBlob` observation; CXF `credBlob` equality | Completed applicable blob imports | RQ2 | Mixed executed and representation evidence |
| CLM-05 | Migration outcome depends on path | Matched credential/final-provider outcomes across direct and multihop routes | Registered matched route pairs | RQ3 | Corrective control evidence |
| CLM-06 | Unknown/versioned data causes reject, preservation, or degradation | Execution and semantic axes by registered mutation family | All robustness cases | RQ4 | Corrective control evidence |
| CLM-07 | Import is or is not idempotent | Final credential count and semantic state after repeated import | All registered retry sequences | RQ4 | Corrective control evidence |
| CLM-08 | Failure handling is atomic or recoverable | Durable state before failure, after failure, and after retry | All fault sequences | RQ4 | Corrective control evidence |
| CLM-09 | A behavior violates CXF/CXP | Minimal case plus applicable requirement-matrix ID | Cases assessed against that requirement | RQ1–RQ4 | Normative |
| CLM-10 | Migration changes the instrumented clone set | Ground-truth provider copy-set delta | Synthetic instrumented cases only | Exploratory | Exploratory |

Prohibited substitutions:

- Parser acceptance cannot substitute for CXF conformance.
- Direct cryptographic signing cannot substitute for a WebAuthn ceremony.
- Preservation in a reference profile cannot substitute for vendor evidence.
- A simulated or deliberately lossy control cannot be counted as a discovered
  implementation defect.
