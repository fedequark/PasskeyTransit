# Public CXP draft envelope: synthetic structure probe

Date: 2026-10-20. Source: [FIDO CXP Working Draft, 2024-10-03](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html), especially sections 3.2–3.5. This is an exploratory test of the draft's visible object and archive shapes, not a conformance result.

Run from the repository root:

    python tools/run_cxp_wire_probe.py
    $env:PYTHONPATH='src'; python -m pytest tests/test_cxp_wire_probe.py -q

The first command writes experiments/cxp_wire_structural/report.json. The fixture has one synthetic index JWE and one synthetic document JWE in a deflated ZIP. The JWE files are valid direct-key AES-GCM compact serializations solely to make the archive structurally testable. The response advertises draft HPKE parameters, but those parameters do not encrypt the JWE fixture.

The positive probe checks request and response members, offered suite and archive selection, canonical base64url, ZIP paths, member count and size, deflate compression, and five-part JWE syntax. Nine automated tests include mutations of version, archive, HPKE selection, encoding, archive paths, and plain JSON substituted for JWE.

The draft's narrative mentions a signed challenge, but its displayed request and response schemas omit the challenge and signature members. It also requires JWE files encrypted with the selected HPKE parameters without giving a complete mapping from HPKE encapsulation to JWE protected header, content key, or archive member. The draft points to a CXF ZIP archive, while the current CXF Proposed Standard describes JSON data structures and does not define that archive layout. Consequently the probe reports JWE authentication under HPKE, challenge verification, CXF plaintext recovery, and provider interoperability as NOT_EVALUABLE. The fixture cannot be imported by an external provider.

The structural probe catches clear envelope mistakes before a provider run. A separate [experimental ZIP/JWE profile](CXP_ZIP_JWE_EXPERIMENT.md) now encrypts and decrypts synthetic files with positive and negative controls. That private mapping still needs agreement by an external provider or a revised specification before it can support a CXP interoperability claim.

## Open-source implementation candidate: Bitwarden type definitions

On 2026-10-21 we inspected the public Bitwarden `credential-exchange-protocol` Rust types at pinned commit `32da4c8b0a4abdd0b46fae79c31e0fdb50150396` ([source](https://github.com/bitwarden/credential-exchange/blob/32da4c8b0a4abdd0b46fae79c31e0fdb50150396/credential-exchange-protocol/src/lib.rs)). Its README says the crate targets the 2024-10-03 Working Draft. The declared `ExportRequest` has `version`, `hpke`, `importer`, `credentialTypes`, and `knownExtensions`; `ExportResponse` has `version`, `hpke`, `exporter`, and `payload`. Compared with the [public draft's displayed objects](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html), the Rust types omit `archive` and `mode` from the request and `archive` from the response. The Rust `Version` converts through `u8`, whereas the draft uses a two-byte unsigned integer. Run `python tools/run_cxp_schema_gap.py` to regenerate the comparison from a pinned fact snapshot; see `experiments/cxp_external_schema/report.json`.

## Executed external parser probe, 2026-10-26

The pinned Rust crate was compiled in GitHub Actions with a committed Cargo lockfile and fed the synthetic request and response. [Run 40324657477](https://github.com/fedequark/PasskeyTransit/actions/runs/40324657477) passed; its JSON output is `experiments/cxp_external_schema/runtime_report.json`. The parser accepted both objects, but serialization omitted request fields `archive` and `mode` and response field `archive`. It rejected version 256, which fits the draft's 16-bit field but is **not** a published protocol version. This is a future-width limitation, not a current conformance failure. The report verifier checks those exact outcomes. The source revision and fixture are pinned, and the workflow uses `cargo run --locked`.

This is an executed **type-parser** result, not a provider transfer or a decryption test. The omitted fields illustrate semantic loss during this parse/serialize route; they do not establish how a provider application would handle the original wire object. The crate README describes type definitions, not a complete exchange engine. HPKE/JWE decryption in these external parsers and public provider interoperability remain NOT_EVALUABLE. The separate project-defined cryptographic profile does not change that external-provider result.

## Second open type parser: Go

On 2026-10-26, [run 40326863069](https://github.com/fedequark/PasskeyTransit/actions/runs/40326863069) compiled [`go-cxp`](https://github.com/nvinuesa/go-cxp) at commit `94659f317ac62470a149cb3ecb769ed5d03d18a1` and applied the *same* synthetic fixture. Request and response parsing passed. In contrast with the pinned Rust types, the Go types retained `archive` on both objects; they still discarded outer request `mode` and rejected version 256. The CI output is `experiments/cxp_external_schema/go_runtime_report.json`, verified by `tools/verify_go_cxp_runtime_report.py`. This is a cross-language **type-parser comparison**. The Go library also describes itself as message type definitions; neither run decrypts the payload or transfers a credential between providers.

Run `python tools/compare_cxp_type_parsers.py` to regenerate `experiments/cxp_external_schema/comparison.json` from the two verified CI reports. It lists only three draft-required envelope members: Rust retains none after a parse/serialize round trip; Go retains both `archive` members but loses request `mode`. Both version-width probes reject 256, which is not a published version. The anonymous artifact verifier recomputes the matrix from the included reports.
