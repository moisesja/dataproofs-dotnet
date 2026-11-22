# PR #62: one more thorough review (round 6, whole PR)

**Owner's intent.** "Give it one more thorough review." The PR was judged ready at 7f4e50e (review 6009946736).
This pass looks at the whole PR as it would merge, main to head, with reviewers who have not seen my conclusions,
and covers whatever the author pushes in answer to that review. Reviewer only: no product source edits, no merge,
no push.

**State found (2026-11-22 14:18Z).**

- GitHub head was still `7f4e50e`. No review or comment since 6009946736.
- The author's local branch was three commits ahead and not pushed: 8e30ac5 (the docs and test items I asked for),
  5d40562 (a suite's own `VerifyProof` now verifies copies; the commit says the owner chose to fix it in this PR),
  907b420 (`Own` maps `ObjectDisposedException` only when the document is disposed).
- At 14:54Z the author pushed `e91c656`: those three plus 8786435 (tests) and e91c656 (documents and comment
  wording). `git diff 907b420 e91c656 -- src` changes comments and XML docs only.

**Decisions.**

- Earlier rounds were incremental. This one is the whole diff `e4e3026..head`, in dimensions the increments did
  not cover: what changes for a consumer upgrading from main, whether every changed line is pinned by a test, and
  whether every documented statement is true.
- Behaviour work started against the unpushed candidate `907b420` so nothing waited on the push, and was
  reconciled with `e91c656` when it landed. The document audit waited for the pushed head.
- Four fresh sub-agents (adversarial on the new `VerifyProof` code, upgrade differential, mutation sweep, document
  audit). No Workflow: the owner did not ask for one.
- I read the whole source diff myself and re-ran every sub-agent finding I cite as fact.
- The RDFC allocation finding is outside this PR and shaped like a denial-of-service lever, so it went to the owner
  only, not into the public review.

## Checklist

- [x] PR state, reviews, comments; found the unpushed commits
- [x] Sub-agent: adversarial pass on `7f4e50e..907b420` (`VerifyProof` copies, conditional catch)
- [x] Sub-agent: upgrade differential, main against candidate, every entry point and suite, ordinary inputs
- [x] Sub-agent: mutation sweep over every source line the PR changes, plus an audit of the new tests
- [x] My own read of the whole source diff, final state of each file
- [x] My own race check of a suite's `VerifyProof` (83 of 400,000 at 7f4e50e)
- [x] Head pushed: reconciled with `907b420`; build, full suite, CI
- [x] Sub-agent: document audit at the pushed head (CHANGELOG, PRD, XML docs, PR body)
- [x] Re-ran what I cite; drafted, checked every number, posted
- [x] Results here, lesson in `tasks/lessons.md`, scratch worktrees removed

## Results

**Verdict: the code is ready; the written record has four false statements.** No input found for which the head
signs or verifies the wrong thing.

- **At e91c656, mine.** Release `/warnaserror`: 0 warnings. 4,816 tests, 0 failed, 0 skipped (ApiSurface 7, Cose 129,
  DependencyInjection 11, Core 731, Jose 2,071, Legacy 599, Rdfc 1,268). CI 12 of 12.
  - Suite `VerifyProof` race, my round-5 cell: 0 of 400,000 (83 of 400,000 at 7f4e50e).
  - Baseline race, other document kept alive: 0 of 300,000 each for `AddProofAsync`, suite `CreateProofAsync`,
    `Verify`.
- **Adversarial pass (reported).** 0 wrong of 15,106,000 raced calls against 55 of 4,499,000 at 7f4e50e. The
  author's four caller-code routes are open at 7f4e50e and closed at the candidate (263 of 263 cells correct, 82
  wrong before). It reproduced my 83 cell at 7f4e50e (14 and 34 per 200,000). `OperationCanceledException` still
  escapes `VerifyProof` (pre-existing filter).
- **Upgrade differential (reported).** About 130,000 cases. Same bytes for every input issued on both sides except
  54 bbs-2023 cases with a collection that misreports `Count`. Pipeline `Verify`/`VerifyAsync` identical in 43,314
  of 43,314. Changes I re-ran on main and head:
  - a suite's `VerifyProof` result carries a copy of the proof (documented, condition too narrow);
  - `PreviousProofReference.Values[i]` out of range throws `IndexOutOfRangeException`, was
    `ArgumentOutOfRangeException` (in the PR since 0da55a9; I missed it for four reviews);
  - legacy RDFC `VerifyProof` now fails a proof whose `@context` is from a disposed document (documented).
- **Document audit (reported, then read by me).** Four false statements: CHANGELOG lead :25-26; CHANGELOG :580-581
  (caused by item 6 of my last review, which compared two PR heads and not main); `JsonInputCheck.cs:149-150`; the
  PR description's "Error precedence is as on main". About a dozen statements true only with a condition.
- **Mutation sweep (reported).** 162 mutants, 129 killed, 33 survive, 22 real gaps. The top one I re-ran: with JCS
  `VerifyProof` hashing the caller's proof instead of its copy, all 731 Core tests pass; the row 8786435 removed
  (`VerifyProof_ReadsTheProofOnce`) was the only one that caught it. 34 new test cases cannot fail for the reason
  in their name.
- **One-line fix tried in scratch.** `=> ((IReadOnlyList<string>)ids)[index];` restores main's exception type; 0
  warnings, 187 related Core tests green.

**Outside the PR (owner only).** RDFC verification allocates quadratically in the number of values of one
property. eddsa-rdfc-2022 `VerifyProof`, one array property of 96-character strings: 125 values 23 MB, 250 values
63 MB, 500 values 214 MB, 1,000 values (91 KB document) 793 MB. The same document with 1,000 distinct members
allocates 56 MB. Identical on main e4e3026 and on e91c656. Not investigated further. Probe and outputs are in
`tasks/pr62-review-artifacts/rdfc-allocation/`.

## Published

Review 6013027106 on e91c656, 2026-11-22T15:30:29Z:
https://github.com/moisesja/dataproofs-dotnet/pull/62#pullrequestreview-6013027106

Asked for before merge, in one commit I do not need to see unless it changes other source: the four false
statements, the removed row restored, and the one-line indexer.

The 36 rows the sweep wrote for the test gaps, with the mutant table, are in
`tasks/pr62-review-artifacts/gap-rows/`. All scratch worktrees are removed (mine and the sub-agents'). No source in
the owner's checkout was edited.
