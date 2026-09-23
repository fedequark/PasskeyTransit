# Artifact review PasskeyTransit v0.7.1

Artifact verdict: **Accept**. Confidence: **5/5**.

Reviewed release: `v0.7.1`, archive SHA-256
`3d9cbf83400fbf5237fca831ab566c5186700e97691e204945bbd4d555200627`.
The archive records source commit `4b7b9bc74a16325504a6250938e6f7eddfa84c87`.

The release verifier passed all entry hashes, 10,400 unique browser challenges,
5,200 primary transcripts, 5,200 signed extension witnesses, 5,200 reconstructed
`largeBlob` oracles, four raw-to-summary derivations, and seven regenerated
publication outputs. The archive has 117 unique entries and excludes prior
reviews, prior releases, `paper/current`, and `paper/legacy`.

Independent recalculation from archived JSONL reproduced 6,144 C1 attempts,
5,120 imports, 1,024 pre-ceremony rejections, 2,304 complete PASS outcomes,
512 false-reassurance outcomes over 5,120 successful assertions, 80 C2 cases
with 64 rejections, and 960 C3 sequences with 832 simulated atomicity passes and
128 deliberate failures. All 96 route-by-stratum groups contain 64 executions
and are internally homogeneous; only 18 outcome vectors occur. The manuscript
correctly treats these as designed-control results rather than independent or
population-sampled evidence.

Two cleanly repacked adversarial archives were tested after removing the audit
fields from their external manifests. A raw semantic-class mutation was rejected
because raw evidence no longer reproduced the C1 summary. A coordinated
`largeBlob`/oracle/hash rewrite was rejected because the signed witness no longer
matched its attempt context. Duplicate and undeclared ZIP entries are also
rejected. The test suite passed 70 tests.

