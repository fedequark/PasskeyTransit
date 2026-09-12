# Phase 4 — CXP/HPKE reference transport

## Outcome

Phase 4 implements an executable reference exchange between an importer and an
exporter. It transports the standards-aligned CXF passkey document from Phase 2
using real RFC 9180 HPKE and verifies the recovered CXF before accepting it.

The implemented profile is deliberately narrow:

- CXP Working Draft version `0`;
- `direct` response mode;
- HPKE `base` mode;
- KEM `0x0020`: DHKEM(X25519, HKDF-SHA256);
- KDF `0x0001`: HKDF-SHA256;
- AEAD `0x0001`: AES-128-GCM;
- raw RFC 1951 `deflate`;
- one canonical JSON CXF passkey document.

## Checks

The suite includes the official RFC 9180 Appendix A.1 base-mode vector plus
end-to-end checks for suite negotiation, unknown-suite skipping, downgrade
refusal, ciphertext tampering, challenge binding, exporter-metadata binding,
wrong recipient key, replay, and invalid CXF input.

`_passkeyTransit` is an explicit experimental extension. It supplies the
challenge/request identifier and HPKE encapsulated key that the Working Draft
narrative requires but its JSON structures do not define. The complete gap
analysis is in `docs/CXP_DRAFT_GAPS.md`.

## Reproduction

```powershell
./research.ps1 test
./research.ps1 cxp-requirements
./research.ps1 cxp
```

The final command writes only aggregate, non-secret run data to
`datasets/generated/cxp_phase4_result.json`. Importer private key material,
challenge values, CXF plaintext, and ciphertext are not persisted by the
runner.

## Evidence classification

This is a protocol reference implementation, not an interoperability result.
No external CXP provider is exercised and no claim is made for the Working
Draft's underspecified ZIP/JWE payload or signed-challenge flow.

## Frozen sources

- FIDO Alliance, Credential Exchange Protocol v1.0 Working Draft,
  2024-10-03: <https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html>
- RFC 9180, Hybrid Public Key Encryption: <https://www.rfc-editor.org/rfc/rfc9180>
- IANA HPKE registries: <https://www.iana.org/assignments/hpke/>
