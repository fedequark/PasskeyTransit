# CXP-shaped ZIP with JOSE HPKE-3-KE members

Date: 2026-10-26. This experiment combines the [JOSE HPKE Internet-Draft -22](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt-22) JWE key-encryption mapping with the [CXP Working Draft](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html) visible ZIP shape. The JOSE cryptography is processed by the independent `jwx/v4` Go library. The ZIP index, context envelope, and CXP transport binding are **project-defined**.

The Python exporter builds a deflated ZIP with `CXP-Export/index.jwe` and one `CXP-Export/documents/<id>.jwe`. Each is a five-segment compact JWE with `alg=HPKE-3-KE`, `enc=A128GCM`, and the HPKE encapsulated key in the protected `ek` header. A fresh key, IV, and HPKE ephemeral key are used per member. The encrypted plaintext of each JWE contains the member name, a digest of the request and selected response metadata, and the index or synthetic CXF content. The adapter passes both JWEs to `jwx/v4` for decryption; project code then checks index membership, request binding, negotiation, context digest, and CXF shape.

The [report](../experiments/cxp_jose_zip_go/report.json) records five passing controls: a recovered synthetic CXF document, and rejection of a modified index JWE, wrong recipient, changed exporter, and unoffered archive. It stores only digests, result booleans, library/tool versions, and limitations. The local verifier checks source hashes. This is a stronger wire exercise than the isolated JWE test, but the external library is **not a credential provider** and does not import or assert a passkey.

## Reproduce

After building `tmp/jose-hpke-go.exe` as described in [the JOSE interoperability note](JOSE_HPKE_EXTERNAL_CRYPTO.md):

```powershell
python tools/run_cxp_jose_zip_go.py tmp/jose-hpke-go.exe (Get-Command go).Source
python tools/verify_cxp_jose_zip_go.py
$env:PYTHONPATH='src'
python -m pytest tests/test_cxp_jose_zip_profile.py -q --basetemp tmp/pytest-cxp-jose-zip
```

The exporter identity is compared to an expected string and included in the encrypted context digest. It is **not authenticated as a provider identity**. The challenge hash is not a signed challenge. There is no durable replay store, Android transfer event, provider vault import, or later WebAuthn assertion. A complete provider-level CXP claim remains `NOT_EVALUABLE`.
