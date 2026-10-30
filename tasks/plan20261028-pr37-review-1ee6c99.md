# PR #37 re-review at 1ee6c99

Owner intent: Review the updated PR and publish a verified verdict.

Scope: 1ee6c993ceba792198e795d5f303cc7b3c93a5d9 against main 21ecbaea3e5bd068d9ffc0a2111f8197ecbc066c, focusing on new changes since d01527a and the previous regression cases. Use an immutable archive, scratch probes and one independent reviewer. No production edits.

- [x] Read PR metadata, latest commits, diff and project lessons.
- [x] Review alias collection, selective rewrite and regression coverage.
- [x] Run solution tests, prior probes and additional controls.
- [x] Confirm remote head and CI, then publish review.

## Results

Posted https://github.com/moisesja/dataproofs-dotnet/pull/37#pullrequestreview-5688560817 on unchanged head 1ee6c99. Verdict: P1 chained aliases bypass indexed-set detection; P2 inactive scoped aliases remove ordinary JSON property coercion and reject lossless documents. Both independently reproduced against d01527a under Ed25519 and P-256, including negative controls and unchanged baseline proofs. Sources and logs: `/private/tmp/pr37-1ee6c99-probes/confirmed-old` and `confirmed-new`, plus sibling logs.

All 2,842 solution tests passed with no failures/skips; CI run 40746426749 succeeded. Both previous P2s are fixed, including verification of unchanged baseline proofs. Prior indexed-set/direct-alias, IRI-collapse, JSON literal and BBS probes retain expected results. No production edits.

The independent reviewer identified the scoped-alias hypothesis before its turn failed with a safety error. Main reviewer independently reproduced it and the chained-alias finding; no unverified claim was published. User requested faster completion; posted promptly once both signed-proof reproductions completed.
