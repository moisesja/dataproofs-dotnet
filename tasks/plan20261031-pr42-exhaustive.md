# Comprehensive PR #42 review

Owner intent: exhaustively reassess the entire PR and its risky decisions, not merely confirm earlier findings. Publish a detailed evidence-backed review; do not modify production code.

Target: 1c32d89b13750703e81b41002a58605f373a3f39 against 3fd0115dcbcc9dce0f0477a3948cdf4dd0580ce4. Isolated archive: /private/tmp/pr42-exhaustive-1c32d89. Preserve existing workspace changes.

- [x] Pin current head, read title/description, history and response to previous reviews.
- [x] Audit context policy semantics, nested contexts, retrieval order, and compatibility.
- [x] Audit BBS lifecycle, pointer semantics, proof parsing/limits, mandatory binding and interop.
- [x] Audit vendored canonicalizer against upstream/spec, work limits, serialization and migration.
- [x] Audit public API, documentation/examples, test quality and CI/release decisions.
- [x] Run full suite and independent targeted probes; distinguish introduced defects from existing limitations.
- [x] One adversarial reviewer challenges security findings; no multi-agent workflow.
- [x] Recheck head and publish full findings, decision assessment, evidence and remaining limits.

Decisions: retain earlier evidence but re-evaluate against final design. A documented regression still needs a technical justification. Owner-approved scope is not evidence of correctness or release necessity. No claim of absolute exhaustiveness or security proof; record which areas and experiments were actually reviewed.

## Results
Posted a changes-required COMMENT review on the same head via authenticated GitHub CLI; verified its content through the connector. Full body: /private/tmp/pr42-exhaustive-review.txt.

- Full solution: 3100 passed, zero failed/skipped, native BBS enabled. Cached restore with NuGetAudit=false; not a dependency-vulnerability audit. Current CI run 41214633915: all 12 jobs successful.
- P1 residual: nested-context selection mandates a different existing predicate. Real BBS disclosure verifies without the intended mandatory claim. Also reproduced on base; reject unsupported nested-context precondition or preserve semantics.
- P1 residual: recursive array compaction changes mandatory whole JSON literal [null,1] into existing sibling [1]. Disclosure verifies without intended literal. Also reproduced on base; track sparse selection arrays, preserve copied literal data.
- P2 new regression: dropping proof context after RDF-preserving root-context change returns an unverifiable disclosure. Base passes; restoring proof context alone fixes head verification.
- P2 residual: valid blank labels _:foo-bar, _:foo_bar, _:é issue/derive then fail verification. Base also affected. Scratch scanner correction verified by reviewer, source restored.
- Independent code-point-order assertion fails as expected; four input-label canonical invariance controls pass. Deliberate UTF-16 policy contradicts unconditional conformance claims.
- Suspected CBOR declared-count allocation issue refuted; no finding. Many-to-one RDF labels did not establish a stronger unauthorized claim; excluded.
- Decision assessment includes local canonicalizer provenance/removal safeguards, URI allowlist versus pinned context content, raised proof limit versus total verification cost, constructor source compatibility, stored-proof migration, and broad scope/reproducibility.
- No production edits or merge/release. Tests/probes remain in isolated scratch archives. Review did not independently rerun maximum-size cost benchmarks or audit native crypto internals.
