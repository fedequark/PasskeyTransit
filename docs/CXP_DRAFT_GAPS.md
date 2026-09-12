# CXP Working Draft gap record

Baseline examined: **Credential Exchange Protocol v1.0 Working Draft,
2024-10-03** (<https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html>).
This record prevents experimental choices from being mistaken
for normative CXP behavior.

## G-01 — challenge narrative has no schema representation

Section 2 says that the request includes a challenge, the exporter signs it,
the response carries the signed challenge and the source public key, and the
importer validates it. Neither `ExportRequest` in section 3.2 nor
`ExportResponse` in section 3.3 defines a challenge, signature, signing
algorithm, or verification-key member.

**Phase 4 treatment:** `_passkeyTransit` carries a random challenge and request
identifier. Both are authenticated, together with request and response
metadata, as HPKE AAD. This detects mix-up and modification but is not the
exporter signature described in section 2. HPKE base mode does not authenticate
the exporter identity.

## G-02 — no HPKE encapsulated-key field

`HPKEParameters.key` is described as the provider key needed by the other
party. The response requires an offered `HPKEParameters` entry, while RFC 9180
also requires the sender to convey the KEM encapsulated key (`enc`). The
response schema has no dedicated `enc` member, and changing `key` would make
the response cease to correspond to the offered request entry.

**Phase 4 treatment:** the selected response `hpke` remains byte-for-byte equal
to the offered entry; `_passkeyTransit.enc` carries the X25519 encapsulated
public key.

## G-03 — payload layering is underspecified

Section 3.4 requires a CXF ZIP archive whose files are individually encrypted
as JWE using a key defined by the selected HPKE parameters. It does not define
the mapping from HPKE output to JWE algorithms, headers, nonces, file names, or
the `payload` representation of the archive.

**Phase 4 treatment:** a canonical JSON CXF document is compressed with raw
DEFLATE and encrypted once with HPKE. ZIP and per-file JWE are deferred. The
runner reports `normative_interoperability_claimed: false`.

## Security boundary

The implementation demonstrates RFC 9180 confidentiality/integrity, parameter
negotiation, CXF validation, request binding, downgrade refusal, and local
replay rejection. It does not demonstrate authenticated exporter identity,
portable durable replay state, user authorization, provider attestation, or
interoperability with an independent CXP implementation.
