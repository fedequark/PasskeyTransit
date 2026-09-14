# Phase 11 independent CXF implementation

## Selected implementation

The first external adapter targets Bitwarden's open-source
`credential-exchange-format` Rust crate v0.4.0 at commit
`0ee5516e4c0481ab6b0a68f8541fc39c3c3379b1`. The dependency is pinned in
`interop/bitwarden-cxf-adapter/Cargo.lock` and built as WASI so the same adapter
can run without linking to the Python process.

## Adapter contract

The stable protocol is one JSON request on stdin and one JSON response on
stdout. Version 1 supports `cxf-round-trip`: the adapter parses the CXF document
with the external implementation and returns its serialized form plus identified
metadata. PasskeyTransit then validates the result and compares canonical JSON
hashes.

## Claim boundary

A successful result establishes that one synthetic passkey document is accepted
and preserved by the pinned independent CXF parser and serializer. It does not
exercise the Bitwarden application, durable import, WebAuthn behavior or CXP.
Accordingly, it is not evidence about a commercial provider.

Source: https://github.com/bitwarden/credential-exchange/tree/v0.4.0
