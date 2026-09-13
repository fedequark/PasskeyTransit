# Phase 8 — independent implementation boundary and PQC exploration

## Outcome

Phase 8 adds two implementation boundaries that do not reuse the corresponding
PasskeyTransit logic:

1. `cryptography`'s native HPKE implementation exchanges RFC 9180 base-mode
   ciphertexts bidirectionally with `passkeytransit.hpke`.
2. A Node.js consumer independently parses the CXF JSON, imports the PKCS#8
   key, derives the public SPKI, decodes the credential ID, and inflates the raw
   DEFLATE `largeBlob`.

The native HPKE API emits `enc || ct`; the test splits its X25519 encapsulation
and verifies both native-to-reference and reference-to-native directions. Its
single-shot API does not expose a separate AAD parameter, so interoperability
with the experimental CXP AAD profile is not claimed.

## Post-quantum experiment

As a secondary, explicitly out-of-scope experiment, the same native library
executes an ML-KEM-768 + X25519 hybrid HPKE round trip. This demonstrates an
available PQC migration-transport primitive; it is not registered as a CXP v0
suite, has no CXP JWK/framing profile here, and is not included in the primary
estimands.

## Sources

- RFC 9180: <https://www.rfc-editor.org/rfc/rfc9180>
- `cryptography` HPKE API: <https://cryptography.io/en/49.0.0/hazmat/primitives/hpke/>
- FIDO CXP Working Draft baseline:
  <https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html>

## Verified run

With clean source commit `d2893c3`, `cryptography 50.0.1` and Node.js
`v24.18.0` passed every applicable check. The hybrid ML-KEM-768+X25519
encapsulation was 1,120 bytes; its complete encrypted test message was 1,171
bytes. These sizes are descriptive for this one plaintext and suite, not a CXP
wire-format benchmark.
