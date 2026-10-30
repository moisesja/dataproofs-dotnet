# PR #37 full re-review

Owner intent: Review the entire current PR again, including earlier fixes and adjacent correctness/security/scalability concerns; post a new evidence-backed verdict.

Scope: Published head d87ebc2687de2ee8e5497c485b234ec6146502bc against base 21ecbaea3e5bd068d9ffc0a2111f8197ecbc066c. Read cumulative source, tests, docs and API changes. Use one independent adversarial reviewer, an immutable archive, and scratch reproductions. No production edits.

- [x] Read current title, description, history and latest repair.
- [x] Review cumulative implementation, exception contracts and data transformations.
- [x] Review tests, fixtures, documentation, scope and scalability.
- [x] Run solution tests and all previous independent reproductions; check CI.
- [x] Verify any new findings and post review.

## Results

Verdict: do not merge; one independently verified P1 remains. `@index` on an `@set` wrapper disappears without warning during expansion, so signing succeeds and adding/changing its metadata leaves both Ed25519 and P-256 verification successful. Actual name changes fail, ordinary sets pass, and indexed value objects correctly fail. Requested a semantic fix with alias and opaque JSON-literal controls.

Published review and inline finding: https://github.com/moisesja/dataproofs-dotnet/pull/37#pullrequestreview-5686538504 . Remote head was rechecked immediately before posting and still matched the reviewed commit.

Validation: 2,813 tests passed with no failures/skips in `/private/tmp/dataproofs-pr37-full-d87ebc2`; all 12 jobs of CI run 40730162175 succeeded, including native AOT parity. Re-ran the three previously reported reproductions and confirmed all fixes, including direct and pipeline BBS reveal verification.

New independent reproduction: `/private/tmp/pr37-full-adversary/Program.cs`, verified output `/private/tmp/pr37-full-adversary/confirmed-output.txt`. The single adversarial subagent supplied the initial case; the main reviewer reran it with native cryptography and additional controls after that agent's turn ended with a tool-side safety error. No unverified agent claim was published.

Cumulative review covered source, public APIs, error mapping, context loading, tests, fixtures, samples, provenance documentation and migration notes. Scope is justified by shared canonicalization. Generic history subjects were noted as minor cleanup. Extra expansion/set memory/BBS passes were assessed statically; no large-input performance bounds were claimed. No production files were changed.
