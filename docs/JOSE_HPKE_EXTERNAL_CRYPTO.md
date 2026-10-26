# External JOSE HPKE cryptographic interoperability

Checked 2026-10-26. [JOSE HPKE draft -22](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt-22) defines `HPKE-3-KE` for X25519, HKDF-SHA256, and AES-128-GCM key encryption. It is an active Internet-Draft in the RFC Editor queue, **not a published RFC**. The independently maintained [jwx/v4 library](https://github.com/lestrrat-go/jwx/tree/v4.6.0) supports this algorithm. We pinned v4.6.0 and Go 1.26.10, ran both directions locally, and retained only hashes and boolean results in [`report.json`](../experiments/jose_hpke_go_interop/report.json).

| Item | Earlier project ZIP/JWE profile | JOSE draft -22 test |
|---|---|---|
| `alg` | Private `urn:passkeytransit:hpke-wrap-v1` | `HPKE-3-KE` |
| Encapsulated key | First 32 bytes of JWE encrypted-key segment | Base64url `ek` protected-header parameter |
| JWE encrypted-key segment | Encapsulated key, HPKE-encrypted CEK, tag | HPKE-encrypted CEK and tag |
| HPKE `info` | Project-specific label | `JOSE-HPKE rcpt\xffA128GCM\xff` with empty recipient extra information |
| HPKE AAD | Protected header plus request/response digest | Empty |
| Content encryption | JWE `A128GCM` | JWE `A128GCM` |

The earlier private mapping remains an explicit project test profile. The JOSE draft does **not** define CXP transport negotiation, exporter identity, ZIP member naming, provider authorization, or vault import. We have therefore tested **JWE cryptography only**, using one synthetic CXF document as plaintext. This is a real interoperability step with an independently maintained cryptographic implementation, but not a complete external CXP implementation.

## Reproduce

Install Go 1.26.10 and the locked Python dependencies, then from the repository root:

```powershell
$env:GOEXPERIMENT='jsonv2'
Push-Location interop/jose_hpke_go
go mod download
go build -o ../../tmp/jose-hpke-go.exe .
Pop-Location
python tools/run_jose_hpke_go_interop.py tmp/jose-hpke-go.exe (Get-Command go).Source
python tools/verify_jose_hpke_go_interop.py
```

The local Go archive was obtained from the [official Go release page](https://go.dev/dl/) and checked against its published SHA-256. The run confirmed Python-to-Go and Go-to-Python decryption equality. Modified JWE ciphertext and wrong recipient keys were rejected. The Go adapter calls `jwe.Encrypt` and `jwe.Decrypt` from jwx; it does not implement HPKE itself. The report excludes the ephemeral keys, encrypted JWEs, and CXF plaintext. The exact Go module checksums are in `interop/jose_hpke_go/go.sum`.

## Remaining gate

A [CXP-shaped ZIP experiment](CXP_JOSE_ZIP_EXPERIMENT.md) now places these JOSE JWEs in a two-member archive and checks transport binding. The next gate is an external credential provider that imports the synthetic credential and produces a later assertion at a controlled RP. The JOSE tests narrow the cryptographic gap; they do not establish that a provider accepts a CXP payload or preserves PRF state.
