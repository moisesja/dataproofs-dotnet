# PR #62 re-review at c5c32c7

Owner intent ("re-review PR 62"): review the PR as it now stands on GitHub and publish a specific review. Same brief as the earlier rounds: title, description, diff, commit clarity, tests, critical paths; brutally honest and specific.

- [x] Read the two author replies (7068110301, 7068257127), the updated PR body, and the diff 0da55a9..c5c32c7 (3e0640e, c5c32c7; 14 files, +742/−142).
- [x] Build and run the whole suite at the unmodified head; check CI.
- [x] Check each fix against the finding it answers: re-run my round-2 and follow-up probes on the head; restore the old sources and confirm the new tests fail (the author's "18 runs" and mutant claims).
- [x] Look for what the two commits newly introduce (the narrowed `OwnedCopy` catch, the new exception rule, the new test helpers) and whether the docs and PR body are true at this head.
- [x] One adversarial sub-agent with its own worktrees, given the diff and the claims, not my findings.
- [x] Head moved to dbcbeb7 while that pass ran (five more commits: the owner had the author fold follow-ups (a)-(d) in). Read the new increment c5c32c7..dbcbeb7, build and test it, re-run every earlier probe on it.
- [x] Second adversarial sub-agent on c5c32c7..dbcbeb7.
- [x] Recheck the head, publish the review, record results here.

Decisions: review `c5c32c789ad3ad6a33857829504da875a681ef7f` against `0da55a9668a1cc4437f59ead1b0ead3b725f0331` (increment) and `e4e302614719c3418aacb3d40217d762876d7e96` (base). Reviewer only: no product source edits in this checkout, no merge, no push. Probes and worktrees live in the session scratchpad and are removed after the run. The author's worktree holds unpushed work beyond c5c32c7 (the owner told it to fold follow-ups (a)-(d) in); that is not on the PR, so it is not reviewed and not touched. If the head moves before I post, the review says which commit it covers. Lesson of the last round applied: nothing goes under "what held" unless it was run.

## Results

Decision when the head moved (dbcbeb7, 23:08Z): the author's comment 7070685236 says dbcbeb7 replaces c5c32c7 for review, so nothing was posted for c5c32c7 alone. One review will cover the current head and close out c5c32c7 in it. A "ready" verdict is not posted before the second adversarial pass reports (the author merges on that verdict).

Run by me so far:

- c5c32c7: release build `/warnaserror` clean; 4,349 passed, 0 failed, 0 skipped; CI 12/12. All six round-2 probe rows pass (FromValues, bbs-2023 both timings, eddsa-rdfc-2022 direct and pipeline, mandatory pointers). Legacy RDFC `KeyType`-disposes-document is `ProofGenerationException`. With 0da55a9's `PreviousProofReference.cs` and `Bbs2023Cryptosuite.cs` restored: 18 runs fail (Core 5, Rdfc 7, Legacy 6), as the author said. With 3e0640e's `LegacyCryptosuiteBase.cs`: the 2 new rows fail. With 3e0640e's Core `JsonInputCheck.cs`: the 4 Core propagate rows fail.
- dbcbeb7: release build `/warnaserror` clean; 4,504 passed, 0 failed, 0 skipped (ApiSurface 5, Cose 129, DI 11, Core 652, Jose 2,071, Legacy 469, Rdfc 1,167); CI 12/12. Follow-up (a): a member renamed to `proof` while the signer runs now returns the document as given and verifies (3 values); a document disposed while the signer runs returns and verifies. (b): `ProofGenerationException` at creation, direct and pipeline. My capture probes can no longer obtain an array at all (`CopyTo` is never called).
- First adversarial pass (on c5c32c7), re-run by me:
  - A caller dictionary that disposes the document when read: `ProofGenerationException` on e4e3026, raw `ObjectDisposedException` on c5c32c7 (a regression against main that rounds 2 and 3 missed), issued and verifying on dbcbeb7.
  - Dispose race on an options value (second thread disposes the pooled document while the entry copy clones it, then re-rents the buffer): 24 of 150,000 raced calls at c5c32c7 and 22 of 150,000 at dbcbeb7 return a proof that verifies over the other document's text; 693 and 751 raw `ArgumentOutOfRangeException`. The pass reports 0 usable proofs on e4e3026 (not re-run by me).
  - Two mutants survive at dbcbeb7 (all 2,288 Core, Rdfc and Legacy tests green with each): keeping the caller's own empty `Dictionary`, and wrapping the dictionary's `InvalidOperationException`.
- Side effect to report: the first sub-agent ran `git worktree prune` once, which I had not asked for. It reports the only entry dropped was another session's `wt-adv-62b`, whose directory was already gone.

## Published

COMMENT review 6009182260 on dbcbeb7 (2026-11-22 00:31Z), https://github.com/moisesja/dataproofs-dotnet/pull/62#pullrequestreview-6009182260. Head rechecked immediately before posting; no review or comment had landed after 7070685236. Verdict: not ready to merge, one blocking item.

- **[P2, regression from e0a2d8d] Dispose race on the entry copy.** Second pass's probe, re-run by me: a second thread disposes the caller's document as the call starts and re-rents the buffers. `AddProofAsync` returned a document that verifies over other content in 134 of 150,000 raced calls at dbcbeb7, 0 at c5c32c7 and 0 at e4e3026 (there every call fails: 133,644 and 138,866 `ProofGenerationException`, the rest raw). Fix checked on the Core copy: `Thread.MemoryBarrier()` and a re-read of `element.ValueKind` after `Clone()`, catch widened to `ArgumentOutOfRangeException`: 0 of 450,000, every caught call "has been disposed", 652 Core tests green. The reasoning was checked against `JsonDocument.Dispose` and `MetadataDb.Dispose` in dotnet/runtime release/10.0. Reported, not re-run: without the barrier 2 of 5.4 million still leak on arm64; the same outcome exists on main for suite `CreateProofAsync` and `Verify`.
- Smaller, asked for before merge: the two surviving mutants above; no test pins the private-key zeroing, the key-pair dispose or the pinning (reported), and the pinned array is sized from the caller's key length before validation; false statements (CHANGELOG 522 and 560: on e4e3026 a null-`@context` JCS proof verifies as returned and fails only after a round trip, run by me; "copying keys runs no code of the caller's" is false for `MemoryManager<byte>`; FR-12 "shares nothing"); `DeriveProof` now lets a pointer enumerator's `ArgumentException` out and the CHANGELOG does not say so (reported); 15 of 53 mutants survive in all (reported).
- Confirmed by the second pass (reported): the author's failure counts for the five commits are exact (87, 6, 3, and 14/16/12); no single-threaded route; bytes unchanged; the copy costs about 1.1 MiB per call on a 900 KB document with no measurable time.
- Correction posted of my round-2 sentence that two lines were the only caller-collection copies; `Concat(selectivePointers).ToList()` was a third.

State at the end: PR head dbcbeb7, CI 12/12 green. My four worktrees and both sub-agents' worktrees are removed; no source in this checkout was edited. Probe sources and outputs stay in the session scratchpad (`adv2/`, `adv3/`, `myout/`, `review-pr62-dbcbeb7.md`). The next head needs its own pass; with the race settled it should be short.
