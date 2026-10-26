# Experimental CXP-shaped ZIP/JWE profile

Date: 2026-10-26. This project-defined profile fills a gap in the [public CXP Working Draft](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html) solely to make an encrypted, testable ZIP. It is **not** a specification of interoperable CXP. The draft depicts a ZIP of JWE files and HPKE parameters, but does not define the key-management mapping between them or a wire field for HPKE encapsulation.

## Private profile `passkeytransit-cxp-zip-jwe-v1`

- Request: draft fields `version`, `hpke`, `archive`, `mode`, and `importer`, plus the project-specific `_passkeyTransit` request ID and challenge. Only direct mode, version 0, deflate, and HPKE base X25519/HKDF-SHA256/AES-128-GCM are implemented.
- Response: draft metadata and base64url ZIP payload, plus a project-specific request ID and challenge hash. This hash does **not** authenticate the exporter or satisfy the draft's narrative signed-challenge language.
- ZIP: deflated `CXP-Export/index.jwe` and one anonymous `CXP-Export/documents/<id>.jwe`. The encrypted index names the sole document; the encrypted document holds one synthetic CXF JSON object. This index format is project-defined.
- Each file is an [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html) five-segment compact JWE with AES-128-GCM content encryption. The protected header names the archive member and carries the private key-management algorithm `urn:passkeytransit:hpke-wrap-v1`. A fresh 16-byte content key, 12-byte IV, and HPKE ephemeral key are generated for **each** member.
- The JWE encrypted-key segment contains the 32-byte HPKE encapsulated X25519 public key followed by HPKE ciphertext and tag wrapping the content key. HPKE uses [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) base mode. Its `info` is `PasskeyTransit experimental CXP ZIP/JWE CEK v1`; its AAD is the ASCII protected-header segment, a zero byte, and SHA-256 of canonical JSON containing the draft ID, complete request, and selected response metadata. The JWE content encryption authenticates the ASCII protected-header segment as AAD. The private `alg` is **not** a registered [JWA](https://www.rfc-editor.org/rfc/rfc7518.html) identifier.
- The importer checks negotiated parameters, expected exporter string, request binding, ZIP names, protected member name, both AEAD tags, CXF document validity, and a process-local replay cache. The exporter string is bound to ciphertext integrity but is **not authenticated as a provider identity**; anyone with the request's public key can produce an encrypted response. The replay cache does not model durable storage.

## Reproduce

From the repository root with the locked Python dependencies and Node.js available:

```powershell
$env:PYTHONPATH='src'
python tools/run_cxp_zip_jwe_profile.py
python tools/run_cxp_zip_jwe_cross_runtime.py
python tools/verify_cxp_zip_jwe_reports.py
python -m pytest tests/test_cxp_zip_jwe_profile.py tests/test_cxp_zip_jwe_cross_runtime.py tests/test_hpke.py -q --basetemp tmp/pytest-cxp-zip
```

The local run checks a positive CXF round trip, preservation of synthetic HMAC credentials, ZIP/JWE shape, and rejection after ciphertext, wrapped-key, recipient-key, archive, exporter, and replay changes. The separate **project-authored** Node importer decrypts the Python-produced index and document; it rejects a tampered index, wrong recipient key, and altered ZIP central-directory CRC. It validates local/central metadata, CRCs, and the end record for this two-member subset. Reports retain source hashes, result booleans, and digests; no private key, raw CXF document, HMAC seed, or decrypted JWE is retained. The parser does not support general ZIP features.

This advances executable cryptographic testing. A separate [JOSE HPKE external-library test](JOSE_HPKE_EXTERNAL_CRYPTO.md) now exercises the Internet-Draft `HPKE-3-KE` mapping; its wire format differs from this private profile. Neither test shows that Bitwarden, Google Password Manager, Fenko, Proton, or another provider accepts a CXP payload. A genuine provider-level finding still requires an agreed CXP use of the JOSE mapping, a complete external implementation, and a recorded importer result.
