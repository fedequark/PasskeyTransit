# Experimental data dictionary

The raw record format is JSONL. Every attempt has one immutable top-level
record plus referenced event/evidence artifacts.

## Identity and provenance

| Field | Type | Meaning |
|---|---|---|
| `protocol_id` | string | Frozen protocol identifier |
| `campaign_id` | enum | `C1`, `C2`, or `C3` |
| `run_id` | string | Unique environment/repetition run |
| `attempt_id` | string | Unique attempt or fault-sequence identifier |
| `credential_id_hash` | hex string | Non-secret stable research identifier |
| `feature_stratum` | enum | `F0`–`F7` |
| `route_id` | enum | Frozen route identifier |
| `seed` | integer | Registered generator/order seed |
| `source_commit` | hex string | Git commit executed |
| `environment_id` | string | Versioned environment manifest reference |

## Treatment and execution

| Field | Type | Meaning |
|---|---|---|
| `provider_chain` | array[string] | Ordered provider implementation IDs |
| `hop_count` | integer | Number of import transformations |
| `mutation_id` | string/null | Registered C2 mutation |
| `failure_point` | string/null | Registered C3 injection point |
| `retry_index` | integer | Zero for initial attempt |
| `execution_status` | enum | `IMPORTED`, `REJECTED`, `ROLLED_BACK`, `PARTIAL`, `ERROR`, `UNKNOWN` |

## Oracle outcomes

Each oracle is an object with `status`, `evidence_ref`, and optional
`requirement_ids`. `status` is `PASS`, `FAIL`, `NOT_APPLICABLE`, or
`NOT_EVALUABLE`.

Required oracle keys are `cxf_structure`, `credential_id`, `rp_id`,
`user_handle`, `public_key`, `webauthn_assertion`, `uv`, `prf_uv`, `prf_no_uv`,
`large_blob`, `cred_blob`, `payments_marker`, `idempotence`, `atomicity`, and
`custody_ground_truth`.

## Derived classifications

| Field | Type | Meaning |
|---|---|---|
| `semantic_class` | enum | Protocol semantic-preservation axis |
| `normative_class` | enum | Protocol normative-assessment axis |
| `basic_auth_pass` | boolean/null | Derived WebAuthn assertion result |
| `false_reassurance` | boolean/null | Auth pass plus another applicable functional failure |
| `exclusion_reason` | string/null | Registered infrastructure-only exclusion code |

## C2 robustness additions

| Field | Type | Meaning |
|---|---|---|
| `mutation_recipe` | object | Non-secret deterministic seed/index/family recipe for reproducing the case |
| `minimal_reproducer_ref` | SHA-256 reference | Digest of the complete ephemeral mutated input |

C2 never stores the complete mutated document because valid mutation cases can
contain passkey private material. Mutation-family summaries are not pooled into
a preservation estimate.

## C3 sequence and event additions

The C3 sequence JSONL contains one record per registered failure sequence. Its
top-level `execution_status` describes the injected initial attempt and
`final_execution_status` describes the retry. `state_before`,
`state_after_failure`, and `state_after_retry` contain only copy counts,
committed counts, and state digests.

The separate C3 event JSONL contains two records per sequence. `retry_index=0`
is the injected attempt and `retry_index=1` is the provider-level retry. This
preserves the 960-sequence analysis unit while retaining 1,920 immutable event
observations.

Raw records never contain private keys, PRF seeds, plaintext credential blobs,
or account PII. Such synthetic secrets remain in access-controlled ephemeral
ground-truth artifacts and are referenced by hash.
