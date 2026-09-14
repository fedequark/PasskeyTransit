# Literature review for passkey semantic migration

## Review question and method

The review asks which standards, implementations and empirical studies address
portability, synchronization, migration semantics or observable passkey
behavior. Searches were run on 2026-09-14 in the FIDO Alliance, W3C, RFC Editor,
USENIX, GitHub and scholarly web indexes. Queries combined `passkey`, `WebAuthn`,
`credential exchange`, `CXF`, `CXP`, `migration`, `portability`, `sync`,
`security`, and `usability`.

Sources were included when they defined the relevant protocol surface, supplied
an identifiable implementation, or reported empirical passkey observations.
Commentary without methods and work unrelated to credential portability was
excluded. This is a reproducible focused review, not a claim of exhaustive
coverage of every authentication paper.

## Included evidence

| Source | Type | Contribution to this study |
|---|---|---|
| FIDO CXF 1.0 Proposed Standard and Errata | Standard | Defines the passkey representation and extension material under test. |
| FIDO CXP v1.0 Working Draft 2024-10-03 | Draft standard | Defines the proposed protected exchange surface and its current gaps. |
| RFC 9180 | Standard | Defines the HPKE reference suite and vectors. |
| W3C WebAuthn Level 3 | Standard | Defines browser-observable assertion, UV and extension behavior. |
| FIDO Multi-Device FIDO Credentials 2022 | Architecture | Locates availability and recovery in provider synchronization. |
| Ramat et al. 2026 | Empirical study | Shows cross-site passkey UX varies across 111 sites and 28 factors. |
| Jannett et al. 2026 | Empirical security study | Measures deployment and RP behavior, but not provider-to-provider migration. |
| Nawrath et al. 2025 | Comparative study | Contrasts device-bound and synced credentials and concentrates synced trust in the provider. |
| Bitwarden credential-exchange v0.4.0 | Open-source implementation | Supplies an independent CXF parser and serializer for Phase 11. |

## Synthesis and gap

The standards specify representation and browser behavior, while empirical work
mainly studies relying-party deployment, security and user experience. The
review found an open-source CXF implementation but no published empirical study
that measures preservation of identity, private-key correspondence, PRF state,
blob semantics, route dependence, atomicity and idempotence together across a
credential exchange. PasskeyTransit addresses that measurement gap with
synthetic controls. The present evidence does not establish provider prevalence
or implementation vulnerabilities.

## Sources

1. https://fidoalliance.org/download-credential-exchange-specifications/
2. https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html
3. https://www.rfc-editor.org/rfc/rfc9180
4. https://www.w3.org/TR/webauthn-3/
5. https://fidoalliance.org/white-paper-multi-device-fido-credentials/
6. https://www.usenix.org/conference/soups2026/presentation/ramat
7. https://www.usenix.org/conference/usenixsecurity26/presentation/jannett
8. https://arxiv.org/abs/2501.07380
9. https://github.com/bitwarden/credential-exchange/tree/v0.4.0
