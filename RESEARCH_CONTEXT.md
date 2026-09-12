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

## Research questions

1. Which properties are preserved by a direct migration?
2. How does preservation change under round trips and multihop routes?
3. Which losses remain invisible to a basic authentication test?
4. How do provider policies handle unknown extensions, downgrade, duplicates,
   and partial failure?

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

