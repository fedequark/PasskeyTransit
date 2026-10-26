# Proton Pass CXP direct-HPKE cross-implementation probe

Checked 2026-10-26. The exporter boundary uses the independently maintained
[Proton Pass common 2.0.0](https://github.com/protonpass/proton-pass-common/tree/2.0.0/proton-pass-common/src/cxp)
module. The annotated `2.0.0` tag object is
`b22db5ca6fef03d0e9467c0305f9af8a2826be35`; it resolves to the source
commit `69a0927f0fe7071243d6c38e404459a69210fdd4`, as recorded in
the checked-in Cargo lockfile.
Our importer independently constructs a request, derives the RFC 9180 base-mode
X25519/HKDF-SHA256/ChaCha20-Poly1305 context, authenticates the response, and
parses the recovered CXF. The [CI workflow](../.github/workflows/proton-cxp-wire.yml)
builds the Rust adapter and runs the Python controls.

The first [CI run](https://github.com/fedequark/PasskeyTransit/actions/runs/40338355980)
passed a **basic-auth-only** fixture: CXF recovery and rejection of a changed
request, wrong recipient key, and tampered ciphertext. The report retains
digests and booleans, never the request private key or CXF plaintext. A second
fixture feeds a separately generated synthetic PRF-bearing passkey to Proton's
CXF importer, then uses its CXP exporter. The independent Python importer
compares credential ID, RP ID, private key, user handle, and both HMAC seeds.
The [expanded CI run](https://github.com/fedequark/PasskeyTransit/actions/runs/40339376482)
passed all eight passkey controls. Proton's software authenticator then used
the recovered passkey: four signatures verified against the source public key,
and four PRF checks matched the source HMAC seeds for two salts. The
[passkey report](../experiments/proton_cxp_wire/proton-cxp-passkey-report.json)
and [basic-auth report](../experiments/proton_cxp_wire/proton-cxp-wire-report.json)
retain only hashes, booleans, counts, source revision, and scope limits.

The [reverse CI run](https://github.com/fedequark/PasskeyTransit/actions/runs/40340554016)
passed Python→Proton import of another synthetic PRF-bearing passkey. Proton
reexported the imported CXF without warnings; credential ID, private key,
and both HMAC seeds matched the independent source, and a corrupted
ciphertext was rejected. The [reverse report](../experiments/proton_cxp_wire/proton-cxp-reverse-report.json)
records seven passing controls. The Rust dependency graph is pinned by
[`Cargo.lock`](../interop/proton_cxp_wire/Cargo.lock).

## Scope boundary

Proton's `ExportResponse.payload` is a direct HPKE ciphertext containing a
single CXF JSON document. Its module uses request bytes as HPKE AAD and the
importer name as HPKE info. The [published CXP Working Draft §3.4](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html#sctn-credential-payload)
instead requires a ZIP archive with separately encrypted JWE members. This
probe tests interoperability with **Proton's direct-HPKE implementation**;
it does not establish conformance to that draft's ZIP/JWE payload, transfer
between two independent provider apps, vault persistence, or an RP assertion.
The passkey fixture uses Proton's library CXF import/export path, not a
deployed account or Android provider transfer. Software assertions were
verified by a local oracle, not by a deployed RP.

| Published working draft | Proton 2.0.0 path exercised here | Consequence |
|---|---|---|
| [§3.2](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html#sctn-export-request) request includes `archive` and `mode` | [`handshake.rs`](https://github.com/protonpass/proton-pass-common/blob/2.0.0/proton-pass-common/src/cxp/handshake.rs) builds neither field | These fields are not negotiated in the tested request. |
| [§3.3](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html#sctn-export-response) response includes selected `archive` | [`cxp/mod.rs`](https://github.com/protonpass/proton-pass-common/blob/2.0.0/proton-pass-common/src/cxp/mod.rs) constructs a response without it | No draft archive selection can be checked. |
| [§3.4](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html#sctn-credential-payload) payload is a ZIP of separately encrypted JWE files | Proton directly HPKE-seals one CXF JSON string | A draft ZIP/JWE importer need not accept this payload. |
| HPKE suite fields allow X25519/HKDF-SHA256/ChaCha20-Poly1305 | [`hpke.rs`](https://github.com/protonpass/proton-pass-common/blob/2.0.0/proton-pass-common/src/cxp/hpke.rs) uses that suite | The primitives interoperate in both directions; this alone does not repair the envelope differences. |
