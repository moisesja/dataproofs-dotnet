# PR #62 re-review

Owner intent: inspect title, description, diff, commit clarity, tests and critical paths; publish a specific review on GitHub.

- [x] Read current PR metadata and earlier review discussion; identify head and base.
- [x] Read all changed implementation, tests and documentation.
- [x] Verify current tests and independently challenge findings with one adversarial reviewer.
- [x] Recheck head, publish the authorized review and record results.

Decisions: review `0da55a9668a1cc4437f59ead1b0ead3b725f0331` against `e4e302614719c3418aacb3d40217d762876d7e96`. Preserve existing workspace edits and prior review artifacts. This is a review, not an implementation request. Test artifacts stay in temporary directories. Posting the review is explicitly authorized.

Session 6c9f501a (third attempt at this head; the two earlier ones published nothing): head and base checked out as detached worktrees in the session scratchpad, probes added there only, removed after the run. One adversarial sub-agent with its own two worktrees, given the diff and the claims, not my findings. Decision: publish as soon as two findings were reproduced on head and base with their fixes checked, without holding for the sub-agent (lesson of 2026-11-20); anything it reproduces goes up as a separate comment.

## Results

Published COMMENT review 6007474359 on 0da55a9 (2026-11-21 18:59Z), verdict not ready to merge. Head rechecked immediately before posting; no other review or comment had landed since 7066246123.

Reproduced, each run on head and base unless noted:

- Unmodified head: release build with `/warnaserror` clean; 4,243 passed, 0 failed, 0 skipped. CI 12/12 green at the head.
- **P2.** `PreviousProofReference.FromValues` copies with `proofIds.ToArray()`, and LINQ passes a caller's `ICollection<string>.CopyTo` the array it returns (checked on .NET 10.0.15). The caller keeps the backing array. Head: an issued bbs-2023 base proof is rewritten and `DeriveProof` throws, both overloads, during signing and after the call. Base: the same probe passes (the removed rebuild protected it). So the round-1 regression is still reachable by a second route. For eddsa-rdfc-2022, directly and through the pipeline, head and base behave the same: the issued proof stops verifying. Six statements in the docs, a test comment and the PR body ("immutable", "no public interface", "every public way") are false at the head.
- Candidate fix `(string[])proofIds.ToArray().Clone()` closes every probe; `Bbs2023KeyStoreTests` (61) and the Core issue-61 and `PreviousProofReference` tests (50) stay green with it. Not run on the whole solution. Reverted after the check.
- **P3, predates the PR.** Same route on the bbs-2023 mandatory pointers (`mandatoryPointers.ToArray()` at `Bbs2023Cryptosuite.cs:363`): the key-store overload issues a proof that cannot be derived. Head and base alike; my PR #60 review missed it. Same one-line fix checked (230 `Bbs2023*` runs green).
- Follow-up (a) of the PR body: through `AddProofAsync`, a document disposed while the signer runs throws `ProofGenerationException` after the signer was called once (head only). Recommended folding it in; owner's call.
- Follow-up (b): confirmed on head and base for eddsa-jcs-2022; recommended a separate issue. `TheProof_OutlivesTheCallersJsonDocuments` pins bytes of a proof the JCS verifier refuses and never verifies.
- Held: restoring 2bef74d's `PreviousProofReference.cs` on the head fails exactly 28 runs (14 Core, 6 Rdfc, 8 Legacy), as the author's reply said; `OwnedCopy` identical in the three vendored files. The review also said the legacy RDFC hoist was equivalent; that was wrong and is corrected under Follow-up.

## Follow-up (adversarial pass)

The sub-agent reported after the review was posted: no forgery, no proof that verifies but differs from what was signed, and it independently confirmed both posted findings. Published as COMMENT review 6007670012 on 0da55a9 (2026-11-21 19:25Z). Each item re-run by me on head and base unless marked reported:

- **Correction of my own review.** "What held" said the legacy hoist of `WithDocumentContext` out of the `try` was harmless. It is a regression: legacy RDFC with a document disposed after the input check (signer `KeyType` getter) throws raw `ObjectDisposedException` on head, `ProofGenerationException` on base. Legacy JCS is raw on both. Fix checked: assign `wireProof` first inside the `try` (361 Legacy tests green).
- P3 regression: bbs-2023 no longer maps an `ArgumentException` from the caller's dictionary enumerator (base's `CopyOptions` caught it).
- Follow-up (a) is worse than stated: a member renamed to `proof` in a caller-owned buffer while the signer runs gives raw `InvalidCastException` or `NullReferenceException` from `AddProofAsync` after signing, head and base alike.
- Mutants that survive: `OwnedCopy` moved below the option checks in `JcsCryptosuite` (583 of 583 Core tests green; a `KeyType`-hook row kills it), and the repeat check under `OrdinalIgnoreCase` in the Core copy. Reported for the other suites and copies, and for the three copy faults on the bbs path.
- Five more over-broad statements listed (ICryptosuite XML doc, `OwnedCopy` summary, PRD FR-2 and FR-12, CHANGELOG ordinal dictionary).

Verdict after the follow-up: still not ready. Blocking: the `FromValues` array and the legacy RDFC raw exception. Owner's calls: whether the mandatory-pointer copy and follow-up (a) are fixed in this PR.

State at the end of the session: PR head still 0da55a9. The author's worktree already holds an unpushed commit 24f8268 (19:14Z, before the follow-up) that changes both `ToArray()` sites; it does not touch the legacy suite or the pipeline. Not reviewed: it is not on the PR. The four scratch worktrees are removed; no source in this checkout was edited.
