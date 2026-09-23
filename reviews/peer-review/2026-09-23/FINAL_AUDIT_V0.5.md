# PasskeyTransit v0.5 final peer review

Date: 2026-09-23

Review profile: empirical systems and security artifact review

## Verdict

Accept within the stated synthetic-control scope. No P0, P1, P2 or P3 findings
remain in the reviewed v0.5 artifact.

This verdict does not extend to commercial credential providers, positive PRF
or `credBlob` behavior, Secure Payment Confirmation, or normative CXP-PQC
interoperability. The manuscript states those boundaries explicitly.

## Evidence reviewed

- protocol `passkeytransit-semantic-preservation-v1.3`;
- source commit `cc599feea4704b798e7cb3f37de326af1e5c4324`;
- complete C1, C2 and C3 outputs generated from a clean source tree;
- v0.5 manuscript, result JSON, generated tables, DOCX and PDF;
- v0.5.0 release archive and manifest;
- capability report and independent interoperability outputs;
- automated and adversarial verification results.

## Independent checks

The review recalculated all four C1 quantities directly from the 5,120 imported
rows rather than trusting the stored derived flags. The resulting counts were
512, 1,792, 2,048 and 2,304, matching 10%, 35%, 40% and 45% respectively.

The browser-evidence audit verified all 5,200 imported transcripts in the
calibration and full datasets. Each challenge was unique, every challenge was
reconstructed from its nonce and row context, every credential ID matched the
row credential hash, and every retained `largeBlob` observation reproduced its
oracle result.

Two adversarial checks were repeated against the newly generated evidence:

1. A valid transcript was assigned to another row, its context was replaced and
   its unkeyed transcript hash was recomputed. The verifier rejected the signed
   challenge mismatch.
2. A retained `largeBlob` observation was modified and its unkeyed extension
   hash was recomputed. The auditor rejected the reproduced oracle mismatch.

The release verifier accepted the archive with no entry-hash mismatch. The
privacy audit found no sensitive field names. The final DOCX and PDF were
rendered independently and all nine page images were checked for clipping,
overlap, broken tables, missing glyphs and orphaned headings.

## Residual limitations

The evidence supports claims about the experimental method and its synthetic
control profiles. It does not estimate real-world prevalence or product
quality. CDP cannot inject preserved PRF or `credBlob` state, so positive
behavior for those properties remains not evaluable. The payment marker lacks
an SPC ceremony, and the hybrid PQC path remains outside the registered CXP
profile. These are declared scope limits, not unresolved inconsistencies in the
reported results.

