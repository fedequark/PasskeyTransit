# Experimental CXP PQC profile requirements

Status: design input only. No interoperability or standards claim is authorized.

Before the exploratory ML-KEM-768 plus X25519 construction can be measured as a
CXP profile, a versioned specification must define all of the following:

- an unambiguous KEM suite identifier and component order;
- public-key and encapsulation encodings, including exact lengths;
- a combiner with domain separation and a stated security rationale;
- binding of CXP version, archive type, importer, exporter and both component
  ciphertexts into the HPKE transcript;
- rejection rules for partial, reordered and downgraded hybrid inputs;
- exporter authentication and replay semantics;
- deterministic positive and negative test vectors;
- an independent second implementation.

Until those conditions hold, results are labeled `OUT_OF_SCOPE`, reported only
as cryptographic feasibility, and excluded from C1 to C3 denominators.
