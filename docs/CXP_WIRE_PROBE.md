# Public CXP draft envelope: synthetic structure probe

Date: 2026-10-20. Source: [FIDO CXP Working Draft, 2024-10-03](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html), especially sections 3.2–3.5. This is an exploratory test of the draft's visible object and archive shapes, not a conformance result.

Run from the repository root:

    python tools/run_cxp_wire_probe.py
    $env:PYTHONPATH='src'; python -m pytest tests/test_cxp_wire_probe.py -q

The first command writes experiments/cxp_wire_structural/report.json. The fixture has one synthetic index JWE and one synthetic document JWE in a deflated ZIP. The JWE files are valid direct-key AES-GCM compact serializations solely to make the archive structurally testable. The response advertises draft HPKE parameters, but those parameters do not encrypt the JWE fixture.

The positive probe checks request and response members, offered suite and archive selection, canonical base64url, ZIP paths, member count and size, deflate compression, and five-part JWE syntax. Nine automated tests include mutations of version, archive, HPKE selection, encoding, archive paths, and plain JSON substituted for JWE.

The draft's narrative mentions a signed challenge, but its displayed request and response schemas omit the challenge and signature members. It also requires JWE files encrypted with the selected HPKE parameters without giving a complete mapping from HPKE encapsulation to JWE protected header, content key, or archive member. The draft points to a CXF ZIP archive, while the current CXF Proposed Standard describes JSON data structures and does not define that archive layout. Consequently the probe reports JWE authentication under HPKE, challenge verification, CXF plaintext recovery, and provider interoperability as NOT_EVALUABLE. The fixture cannot be imported by an external provider.

The structural probe can catch clear envelope mistakes before any future provider run. A later cryptographic experiment must pin an explicit interoperable HPKE-to-JWE profile or use a revised specification, obtain a second implementation, and record a wire transcript with positive and negative decryption controls.
