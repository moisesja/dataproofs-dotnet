# PR #32 review

Owner intent: read the newly opened PR, scrutinize correctness, security, scalability, scope, tests and commit clarity, and post a specific review on GitHub.

Review base `fe59769bcd7e41be1c23b20b9687f75447bc4340` and head `9748094bd663f892368907c8064f9fce87b09faa`. No implementation or release changes are requested. Posting a review is explicitly authorized.

- [x] Identify PR and read repository instructions, lessons, title and description.
- [x] Inspect every changed file, commit messages, affected call paths and existing discussion.
- [x] Verify relevant tests and use one adversarial subagent to challenge potential regressions.
- [x] Recheck head and CI, post the review, and verify it persisted.

Decisions: use one independent adversarial reviewer, not an orchestrated workflow. Treat the documented intentional API compatibility changes as migration facts rather than automatic blockers. Distinguish preexisting bugs from regressions. Review only; do not fix PR code.

## Review results

Reviewed all 59 changed files and 18 commit subjects. Scope is broad but cohesive; commit messages explain package-specific changes and follow-up fixes. No blocking runtime or security regression found. The intentional setter binary break is documented and accepted by repository release policy.

Validation: solution tests passed 1,022 (0 failures/skips); diff whitespace check passed; IL scan self-test passed 7 controls. Existing local smoke binary passed 44 checks with reflection enabled and 44 with reflection disabled via a temporary runtimeconfig; 28 deterministic values matched. Two sandboxed smoke build attempts stalled and were canceled; they are not counted as successful builds. The initial sandboxed smoke execution could not initialize macOS cryptography; the authorized unsandboxed runs passed. Native-AOT evidence comes from successful GitHub CI run 40518564070, including all four legs, comparisons, cross-verification and IL scanning; native publication was not repeated locally.

One independent adversarial reviewer exercised 2,576 model cases: proof, JWS/JWE headers and JWKs, comparing generated versus reflection metadata with identical options against PR model definitions. No output or exception-type differences; this was not a separately built base-assembly comparison. No new runtime/security defect substantiated.

Concern: PRD calls all jobs through ac-12 required for merge, but live GitHub API reports no classic protection on main (404 Branch not protected), no active branch rules ([]), and no repository rulesets ([]). Existing lack of protection predates this PR; the new ac-12 job is not an enforced merge gate. RELEASING explicitly describes human review of CI before release approval, so do not claim the publish path lacks its documented human gate. Request enforcement or accurate wording. Minor nit: AotSmoke.csproj lines 22–25 still describe the superseded DataProofs-only IL scan.

Posted a COMMENT review anchored to `9748094bd663f892368907c8064f9fce87b09faa`: https://github.com/moisesja/dataproofs-dotnet/pull/32#pullrequestreview-5668526458. The connector returned 403 on write; authenticated GitHub CLI succeeded. The review asks for required-check enforcement or truthful maintainer-procedure wording; it does not block on runtime correctness or the preexisting lack of protection. Omitted the stale-comment nit from the posted review because pass-2 edits are actively correcting it.

During finalization, another process introduced uncommitted changes in JcsCryptosuite.cs, AotSmoke.csproj, SmokeMain.cs and a new IlCanary.cs. Preserved all of them. Remote PR head remained the reviewed commit at the final check. Review explicitly excludes future pass-2 changes. No product code or release artifacts were changed by this review.
