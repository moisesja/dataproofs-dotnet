# PR #37 re-review

Owner intent: Re-review the repaired PR and post a follow-up verdict.

Decision: Review published head 970ef033bacd5e1a5c769b370449ae909fe0f693 against previously reviewed 3a190a4. Use an immutable archive and one adversarial reviewer. Do not implement fixes.

- [x] Read updated PR description and identify repair commits.
- [x] Inspect repair diff and regression tests.
- [x] Retest P1/P2, check adjacent behavior, and run solution tests.
- [x] Review independent findings and CI status.
- [x] Post follow-up review and record results.

## Results

Original P1/P2 confirmed fixed with the independent prior inputs. Full solution at 970ef03: 2,812 passed, zero skipped; CI 40719615164 passed including native AOT parity. Inspected final docs-only commit 87eb4ae50bc1e5fe4282fb2d809c65c06a331667.

New P1 confirmed: an accepted BBS JSON literal with @id urn:bnid:_:b0 can lose that member in a reveal while both suite and pipeline verification stay true. Untouched reveal passes; changing a from 1 to 2 fails; raw canonical datasets differ after deletion. The creation/derivation postcondition does not cover verification. Independent reviewer raised the hypothesis before its turn failed; primary reviewer completed the reproduction and controls.

Evidence: /private/tmp/dataproofs-pr37-rereview-bbs/Program.cs and /private/tmp/dataproofs-pr37-rereview-bbs.log. Prior-finding checks: /private/tmp/dataproofs-pr37-rereview-probe.log.

Posted follow-up review anchored to 87eb4ae: https://github.com/moisesja/dataproofs-dotnet/pull/37#pullrequestreview-5685854125. Verdict: original findings resolved, do not merge until remaining BBS verification gap is fixed. No production code edited.
