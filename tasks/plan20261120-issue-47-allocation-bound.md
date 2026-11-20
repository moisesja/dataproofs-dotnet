# Plan — issue #47 follow-up: make the Type Metadata allocation tests deterministic

Branch `test/issue-47-allocation-bound`, from `origin/main` at `55086a4` (the #55 merge). Test-only: nothing under
`src/` changes, so no CHANGELOG, PRD or public API change.

## Owner's intent

From the parent: `Issue47TypeMetadataProcessingTests.Indexed_paths_cost_work_linear_in_the_claims_at_issuance(mandatory: True)`
failed once on `build + test (ubuntu-latest)` ("allocation grew from 1040 to 8200 bytes" against a 6,240 limit) and
passed on rerun with the same tree. The requirements:
- Make the test deterministic and keep what it catches: the review's quadratic case (2.66 GB). Prove it still bites by
  reverting a274a2a's fix locally.
- Check the other allocation and timing assertions added in #47 for the same fragility, and fix them in this PR.
- Show stability over many runs.

## Cause

The test compared two measurements: 4,000 claims had to allocate under six times what 1,000 claims allocated. Since
#55's later rounds, the validator allocates almost nothing per claim, so both measurements are about 1 KB of fixed
overhead. A single stray allocation of a few kilobytes on the test thread during the second measurement (the CI run saw
8,200 bytes) breaks the ratio, though nothing about the code's behaviour changed.

## Decision

Assert an absolute bound on the least of five measurements taken after one warm-up run (`LeastAllocation`). Each bound
sits orders of magnitude away from both today's allocation and the defect's, so neither noise nor a regression can land
on the wrong side.

- **Least of five:** noise lands in some runs, not in all of them, while the defects allocate megabytes in every run.
- **Absolute bound rather than a ratio:** a ratio of two small numbers is exactly what made the original test fragile.

Alternatives considered:
- Raising the ratio threshold only moves the failure to larger noise.
- Larger counts alone make the test slower without removing the ratio's sensitivity at the small end.
- A single measurement with an absolute bound still exposes one run to a spike as large as the margin.

| Test | Today (least of five) | Bound | The defect it guards against |
|---|---|---|---|
| `Indexed_paths_cost_work_linear_in_the_claims_at_issuance` (both variants) | 320 B | 64 B × 4,000 + 64 KiB = 321,536 B | 128.5 MB, a copy per path (a274a2a) |
| `A_wildcard_over_many_claims_reuses_its_selection_lists` | 85,584 B | 256 KiB | 16.3 MB, new lists per step (c16e9bf) |
| `An_integrity_value_with_many_expressions_is_checked_without_allocating_per_expression` | 88 B | 64 KiB (was 4 KiB) | 9.2 MB, a string per expression (2c0e067) |

The integrity test's old 4 KiB bound was the same fragility: one measurement, about 3.9 KB of margin.

There are no timing assertions left in the #47 tests: the wall-clock ones were replaced by deterministic refusals in
#55 itself. The two racing-resolver tests loop 500 times, but their assertions hold for every interleaving.

## Items

- [x] `LeastAllocation` helper; the three tests use it with absolute bounds
- [x] Proof that each still bites. With each defect re-created locally, every test fails:
  - the complete pass for every claim, with a copy of the array per path (a274a2a reverted): both indexed variants fail at 128,512,320 bytes;
  - a new list per step (c16e9bf reverted): the wildcard test fails at 16,283,824 bytes;
  - the pre-2c0e067 `TypeMetadataIntegrity.cs`: the integrity test fails at 9,159,880 bytes.
- [x] Stability: 200 consecutive full runs of the Jose test project (1,697 tests each), 200 passed, 0 failed
- [x] Full suite: 3,668 passed, 0 skipped; build with `/warnaserror` clean
- [ ] PR, CI

## Review
