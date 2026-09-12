# Research context

## Thesis

Syntactic compatibility during credential exchange may be insufficient to
preserve the cryptographic, functional, and operational security semantics of
a passkey.

## Working model

A credential is represented as `C = (I, K, F, S)`:

- `I`: credential and account identity, including RP binding;
- `K`: cryptographic material and public/private-key correspondence;
- `F`: observable functions such as authentication, PRF, and blob access;
- `S`: operational guarantees, degradation handling, atomicity, and custody.

Migration is treated as a transformation `C' = M(C, A, B)`. PasskeyTransit
compares required invariants before and after direct, round-trip, and multihop
routes.

## Frozen research questions (protocol v1.0)

1. To what extent do direct migrations preserve identity, public-key
   correspondence, and an assertion accepted by the original relying party?
2. Among accepted imports, which functions survive, and when does basic
   authentication conceal loss of another applicable function?
3. For the same credential and final provider, does the outcome depend on
   intermediate providers or a round trip?
4. How do implementations handle unknown values, version mismatch, duplicate
   imports, malformed data, and injected failures?

The authoritative design is `docs/EXPERIMENT_PROTOCOL.md`, with the registered
machine-readable configuration in `experiments/protocol_v1.0.json`.

## Evidence boundaries

- The legacy paper is a prototype containing explicitly simulated results.
- The reconstructed v0.1 baseline uses synthetic reference policies.
- A reference policy is not a proxy for a commercial provider.
- The PRF control in v0.1 is a deterministic oracle over synthetic secret
  material, not a browser WebAuthn PRF ceremony.
- Claims about CXF conformance require the future normative requirement matrix.

## Immediate milestone

PasskeyTransit v0.2: complete CXF subset under test, a local relying party,
Chromium virtual authenticators, and one end-to-end migrated WebAuthn assertion.
