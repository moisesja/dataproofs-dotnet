# PR #62 re-review at 7f4e50e (round 5)

**Owner's intent.** "re-review PR 62": review the PR as it now stands on GitHub and publish a specific, blunt
review. This session is the reviewer, not the implementer: no product source edits, no merge, no push.

**State found.** Head `7f4e50e6a91b62db3664024b5d0f8dddd90657d3`, base `e4e3026`, 18 commits, 29 files,
+3533/−129, CI 12 of 12 green. Six commits since my review 6009182260 on dbcbeb7: a0c3cc5 (race fix), d14db51
(bbs-2023 key copy), 6f9da02 (test pins), e453870 (race findings of the author's adversarial pass), bbda58f
(key length), 7f4e50e (docs). Author's reply: issue comment 7072438179.

**Decisions.**

- Review the increment `dbcbeb7..7f4e50e` in depth and re-check the blocking item first-hand with the same race
  harness that produced the 134 of 150,000 (scratchpad `adv3/probes/Adv3RaceProbe.cs`).
- One adversarial sub-agent, given the diff and the author's claims, not my conclusions. It attacks behaviour:
  race variants, exception leaks, other read sites, bbs-2023 raw-key differential. I do the test-pinning
  (mutants) and the documents myself, so nothing is run twice.
- No Workflow: the owner did not ask for one.
- Scratch worktrees live in the session scratchpad and are removed with `git worktree remove`. No `prune`.
- The suite `VerifyProof` race is pre-existing and outside what the PR set out to fix, so it does not block. I
  recommended a CHANGELOG and XML doc sentence plus a follow-up issue, and left "fix it here" to the owner.
- I re-ran the two adversarial findings I cite as facts (the `VerifyProof` race, the `WithKeyCopy` wiring mutant).
  The rest of its report is marked "reported" in the review.

## Checklist

- [x] Read PR state, every review and comment, the author's reply 7072438179
- [x] Read the incremental diff (src, tests, docs)
- [x] Build and run the whole suite at 7f4e50e (claimed: 4,653 tests, 0 warnings)
- [x] Baseline race harness at 7f4e50e: AddProofAsync, suite CreateProofAsync, Verify (three configurations)
- [x] Read the head sources around every changed site; list any caller JSON read that skips the re-read
- [x] Mutants: spot-check the author's 21 and add my own
- [x] New tests: run them repeatedly for flakiness
- [x] Documents: CHANGELOG, PRD, PR body, plan file against the code
- [x] Adversarial sub-agent report read and its findings re-checked where I rely on them
- [x] Draft the review, check every number in it, post it
- [x] Record results here and the lesson in `tasks/lessons.md`; remove scratch worktrees

## Results

**Verdict: ready to merge.** The blocking race is fixed and nothing wrong came out of this head.

- **Build and tests.** Release `/warnaserror`: 0 warnings. 4,653 tests, 0 failed, 0 skipped (ApiSurface 7, Cose 129,
  DependencyInjection 11, Core 695, Jose 2,071, Legacy 525, Rdfc 1,215). New and changed test classes: 15 runs,
  10,140 executions, 0 failed.
- **Race, my harness, eddsa-jcs-2022, 150,000 calls per run.** Seven runs per entry point (three with the other
  document disposed at once, three with it kept alive, one with a 0 to 3,000 spin window):
  - `AddProofAsync`: 0 wrong of 1,050,000 (dbcbeb7: 134 of 150,000). 25,735 `ProofGenerationException`.
  - suite `CreateProofAsync`: 0 wrong of 1,050,000. 20,893 `ProofGenerationException`.
  - `Verify`: 0 `Verified == true` of 1,050,000. 26,988 `ObjectDisposedException`, 8,891 of them mapped from
    `ArgumentOutOfRangeException`.
  - extension-value race: 0 of 450,000 signed another value (dbcbeb7: 22 of 150,000). `OwnedCopy` alone: 0 of
    1,200,000.
  - No other exception type in any cell.
- **Mutants (20, mine).** 18 killed. Survivors: the options `@context` copy without the re-read (all 2,442
  ApiSurface, Core, Rdfc and Legacy tests green) and the memory barrier (already listed by the author). A row for
  the first passes at the head and fails under the mutant (scratchpad `r5/Pr62Probe5.cs`).
- **Adversarial pass (reported unless noted).** 0 wrong answers in 145 million raced calls over 58 cells; IL of
  `JsonDocument.Dispose` on 10.0.15 has the order the fix relies on. Findings:
  - A suite's own `VerifyProof` still returns `Verified == true` for a document the proof was not made over.
    I re-ran it: 83 of 400,000 at the head. Pre-existing; `VerifyProof` is unchanged since main.
  - Replacing the `WithKeyCopy` call in the raw-key entry point with a plain `ToArray()` leaves all 1,215 Rdfc
    tests green. I re-ran it. The tests pin the helper, not its use.
  - Two unlisted, harmless changes in the raw-key overload; a caller's own `ObjectDisposedException` reported as a
    disposed document.
- **Documents.** The CHANGELOG cites my scratch-patch measurement as a measurement of this code, and describes two
  states that never shipped. One comment is off by one. The plan cites off-branch commit d07b52c twice.

## Published

Review 6009946736 on 7f4e50e, 2026-11-22T03:08:15Z:
https://github.com/moisesja/dataproofs-dotnet/pull/62#pullrequestreview-6009946736

Asked for before merge: the CHANGELOG and XML doc sentence about `VerifyProof` with a tracking issue (owner's
decision whether to fix it in this PR instead), and the `@context` test row. I do not need to see that commit
unless source changes.

Scratch worktrees removed (`r5/wt-head`, `r5/wt-mut`, and the sub-agent's six). No source in the owner's checkout
was edited. Probes and raw outputs are in the session scratchpad under `r5/` and `adv4/probes/`.
