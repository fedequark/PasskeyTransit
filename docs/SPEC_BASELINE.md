# Normative specification baseline

Originally frozen for protocol `passkeytransit-semantic-preservation-v1.0` on
2026-09-12 and retained unchanged for corrective protocols v1.2, v1.3, v1.4 and v1.5 on 2026-09-23.

| Component | Frozen revision | Status | Canonical URL |
|---|---|---|---|
| CXF | 1.0 Proposed Standard with errata, 2026-03-09 | Normative baseline for format experiments | https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html |
| CXP | 1.0 Working Draft, 2024-10-03 | Experimental transport baseline; not a stable standard | https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html |
| WebAuthn | Level 3 Candidate Recommendation Snapshot, 2026-05-26 | Ceremony and extension baseline | https://www.w3.org/TR/2026/CR-webauthn-3-20260526/ |
| HPKE | RFC 9180 | Cryptographic transport primitive baseline | https://www.rfc-editor.org/rfc/rfc9180 |
| CDP WebAuthn | tip-of-tree schema captured in each run manifest | Automation interface, not a normative WebAuthn source | https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/ |

## Interpretation rules

1. CXF normative language is evaluated against the errata-integrated document,
   not the legacy Research Draft referenced by the simulated paper.
2. CXP findings must state the exact Working Draft revision and may not be
   generalized to a future Proposed Standard.
3. WebAuthn defines ceremony semantics. CDP is only the automation mechanism
   and cannot be used as authority for a WebAuthn conformance claim.
4. A behavior is labelled a normative violation only when it contradicts an
   identified `MUST` or `MUST NOT` applicable to the tested actor and input.
5. `SHOULD` deviations are reported with their documented rationale, if any;
   they are not automatically classified as violations.
6. Each future campaign manifest must record browser version, CDP protocol
   schema version or hash, operating system, dependency lock hash, Git commit,
   configuration hash, and specification baseline ID.

## Scope-relevant CXF anchors

- Passkey dictionary: section 3.3.12.
- Editable passkey fields: section 3.3.12.1.
- FIDO2 extensions: section 3.3.12.2.
- HMAC credentials: section 3.3.12.3.
- Large blob representation: section 3.3.12.5.
- Unknown enumeration handling: section 2.1.1.
- Version handling: section 3.1.1.
- Conformance: section 7.

This file freezes sources. The completed normative requirement matrices are
`spec/cxf_passkey_requirements_v1.0.json` and
`spec/cxp_requirements_wd_20241003.json`.
