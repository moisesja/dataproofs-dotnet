# PR #37 review

Owner intent: Review the newly opened PR for correctness, security, test coverage, scope and commit clarity, then post a specific review on GitHub.

Decisions: Review head `9b8f03eb643782746b34b3b83bc668d79fa5e52e` against base `21ecbaea3e5bd068d9ffc0a2111f8197ecbc066c`. Do not implement fixes. Use one independent adversarial reviewer. Keep reproduction artifacts outside the source tree.

- [x] Identify PR and read title, description and commit summaries.
- [x] Inspect complete diff, requirements and existing coverage.
- [x] Reproduce concerns and adversarially verify security findings.
- [x] Run appropriate tests and inspect CI.
- [x] Post evidence-backed review and record outcome.

## Review

Reviewed initial head and subsequent published head `3a190a488e9906629edff251b5ee310b1b54fed9`. Initial full solution: 2,776 passed. Latest RDF suite: 547 passed. Latest GitHub CI run 40709270713 succeeded.

P1: Host-only and trailing-slash IRIs pass emission checks separately but distinct RDF statements collapse in store equality. Reproduced unchanged signatures after injecting a second subject with both EdDSA and P-256; distinct-ID control fails. Independent reviewer found canonicalization collision; primary reviewer confirmed signature impact.

P2: New recursive HasBase scan rejects @base inside an opaque @json literal; predecessor preserved the complete literal.

Reproductions: `/private/tmp/dataproofs-pr37-probe/Program.cs`, `/private/tmp/dataproofs-pr37-latest-probe.log`, `/private/tmp/dataproofs-pr37-json-control.log`. No production code edited. The independent agent stopped after reporting the collision; no unreported claims are included.

Posting: GitHub connector review creation returned 403 Resource not accessible by integration; authenticated CLI fallback succeeded. Review posted as COMMENT, anchored to 3a190a4: https://github.com/moisesja/dataproofs-dotnet/pull/37#pullrequestreview-5684898246. Explicit recommendation: do not merge until P1 and P2 are fixed and covered by regression tests.
