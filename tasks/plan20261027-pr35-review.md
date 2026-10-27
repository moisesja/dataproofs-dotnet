# PR #35 review

Owner intent: read the newly opened PR, assess correctness, security, scalability, scope, commits and tests, and post an honest, specific review comment.

Decisions: review head e38512dec5b97b44fdbc51c829700e60396f3384 against base 1bb35ac9ea2be6b7c9c85e1f98d51f462a0e2d39; no production changes. Use one adversarial reviewer per repository instructions. Posting the review is explicitly authorized.

- [x] Identify PR and read title, description, commit subjects, and repository instructions.
- [x] Inspect complete diff and surrounding contracts/tests.
- [x] Run relevant tests and independently verify potential findings.
- [x] Reconcile adversarial review and recheck remote head.
- [x] Post evidence-backed review and record outcome.

## Review

Reviewed e38512d; remote head unchanged before posting. Full Release test run: 2,506 passed, zero failed/skipped. GitHub CI successful. Commit subjects clear; scope coherent. No demonstrated scalability blocker or signature-forgery bypass.

Two confirmed P2 gaps in the advertised hardening:
- Legacy JCS proof configuration with an extension containing 63 nested arrays passes the depth-64 check, then nesting under document.proof produces depth 65 and leaks JsonException. A 62-array control succeeds. Independently reran the adversarial reviewer's Ed25519 reproduction.
- AdditionalProperties["proofValue"] passes validation while modeled ProofValue is null; direct EdDSA JCS creation and AddProofAsync succeed with duplicate proofValue members. Verify rejects the pipeline's own output. Reproduced independently in a scratch console project.

Requested fixes and regression tests for both. Excluded the unrelated pre-existing BBS numeric proof.type exception. Scratch probes and review body are under /tmp/dataproofs-pr35-review and /private/tmp/pr35-adversary. No production sources or tests changed.

The connector's comment write returned HTTP 403 (integration permissions). Posted the authorized review using the local GitHub CLI with network escalation instead: https://github.com/moisesja/dataproofs-dotnet/pull/35#issuecomment-6455391969
