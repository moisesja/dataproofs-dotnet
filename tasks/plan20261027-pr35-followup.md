# PR #35 review fixes and NetCrypto update

Owner intent: thoroughly address valid findings in review comment 6455391969 and update NetCrypto to the latest stable release, all within PR #35.

Decisions:
- Keep DataProofsDotnet at the existing unpublished 1.4.0 release; use the current PR branch.
- Both reviewed findings reproduce at e38512d. Map JSON failures only inside legacy transformation; signer exceptions must retain their types and instances.
- Reject extension keys matching any modeled proof JSON name, including omitted/null members. Use source-generated JsonTypeInfo property metadata with ordinal comparison, preserving AOT compatibility and avoiding a second maintained name list.
- Apply the same guard to all three internal copies; test direct creation, pipeline creation and BBS creation, with valid extension controls.
- NetCrypto 1.7.1 is the latest stable package on NuGet and upstream CHANGELOG as checked 2026-10-27. Keep the dependency update in its own commit.
- User authorized fixes and update on this PR. No merge, tag or package publication.

- [x] Recheck PR head, findings, dependency release and repository instructions.
- [x] Add regressions and demonstrate they fail on the reviewed code.
- [x] Implement fixes; update relevant PRD/CHANGELOG and review records.
- [x] Update NetCrypto and restore; investigate compatibility differences.
- [x] Run full Release build/tests, relevant gates, samples and AOT parity.
- [x] Adversarially review fixes and resolve valid findings.
- [ ] Commit and push to PR #35; update PR description/review response and verify checks.

## Review

Focused pre-fix run: 127 failures, six passing valid-depth/signer-exception controls. After the fixes, all 813 issue-33/35 focused cases pass. With NetCrypto 1.7.1, the full Release build has zero warnings/errors and all 2,653 tests pass (no skips). Source assets confirm NetCrypto/1.7.1. No source migration was required by the dependency update.

The independent adversarial reviewer reran the original depth probe and actual direct-suite collision probes with reflection disabled, checked all 13 reserved names against cold source-generated metadata, verified case-distinct and AdditionalProperties extensions still sign/verify, and checked identical helper bodies. No remaining blocking finding. Added an AOT smoke path to exercise the metadata guard in all three packages before any other serialization initializes it.

All 15 samples exited zero. Dependency hygiene (project and packed graphs), public API scan and samples coverage passed. All four AOT legs (JIT, reflection-disabled, file-based and osx-arm64 native) passed 50 checks each; 28 deterministic values matched, and cross-runtime verification passed 32 checks in each direction. IL scanner self-tests and publish scan passed, with only the reviewed Newtonsoft warnings and canary. The native linker also reported unavailable cached module debug information; executable validation passed.

PR publication in progress. Validation logs: /tmp/pr35-before.log, /tmp/pr35-after.log, /tmp/pr35-full-tests.log and /tmp/pr35-validation/.
