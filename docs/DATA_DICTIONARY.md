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

Each oracle is an object with `status`, a canonical JSON `evidence` payload,
its integrity commitment `evidence_ref`, and optional `requirement_ids`.
`evidence_ref` is the SHA-256 digest of the retained payload; it is not a
substitute for that payload. Browser-derived evidence contains only the
minimum values or hashes needed to audit the decision. `status` is `PASS`,
`FAIL`, `NOT_APPLICABLE`, or `NOT_EVALUABLE`.

Browser rows additionally contain `browser_evidence`: Boolean verification
checks, SHA-256 digests of assertion components, and a public WebAuthn
transcript (authenticator data, client data, signature, synthetic identifiers,
source public key, expected challenge, expected attempt ID, RP ID and origin) bound to
`transcript_ref`. The release verifier independently recalculates the
commitment, signature and every recorded assertion check. Under protocol v1.5,
`extension_witness` contains a second public signed transcript whose challenge
commits to the primary challenge and the canonical retained extension observations.
Private keys, PRF outputs and
blob plaintext are not copied into the analytical row.
`prf_requested` and `prf_observed` distinguish an exercised PRF request from an
unavailable positive-preservation result.

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
| `false_reassurance` | boolean/null | Auth pass plus failure of a browser-executed behavioral oracle (`uv` or `large_blob`) |
| `login_with_nonexecuted_representation_loss` | boolean/null | Auth pass plus loss detected for PRF or `credBlob` without executing that feature through CDP |
| `login_with_any_nonpayment_property_failure` | boolean/null | Union of executed behavior failure and nonexecuted representation loss, excluding payments |
| `login_with_any_observed_property_failure` | boolean/null | Union of all observed failures, including the format-only payments marker |
| `exclusion_reason` | string/null | Registered infrastructure-only exclusion code |

Each imported browser row also contains a signed-challenge binding context with
protocol, run, attempt, credential hash, stratum, route, repetition and provider
chain. Its retained `largeBlob` evidence includes applicability plus expected
and browser-observed synthetic values.

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
committed counts, and state digests. These are observations of an in-process
Python state machine, not durable storage or process-crash recovery evidence.

The separate C3 event JSONL contains two records per sequence. `retry_index=0`
is the injected attempt and `retry_index=1` is the provider-level retry. This
preserves the 960-sequence analysis unit while retaining 1,920 immutable event
observations.

Raw records never contain private keys, PRF seeds, plaintext credential blobs,
or account PII. Such synthetic secrets remain in access-controlled ephemeral
ground-truth artifacts and are referenced by hash.

For browser evidence, each imported row retains a fresh random 32-byte nonce,
the canonical attempt-binding context and the challenge derived from both. The
release auditor reconstructs the challenge, rejects a missing, too-short or
reused challenge, and rejects any transcript whose signed binding does not
match its enclosing row. For v1.5 it also verifies the second challenge and
signature, then recomputes the C1/C2/C3 summaries and all managed text/CSV
publication outputs from the archived raw records.
