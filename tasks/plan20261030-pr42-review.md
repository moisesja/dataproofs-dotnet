# PR #42 review

Owner intent: assess whether PR #42 duplicates too much dotNetRDF and whether its scope and implementation are justified before release.

Review target: 68d2852645a64fb393fcced068eb2f5596cc1bb2 against 3fd0115dcbcc9dce0f0477a3948cdf4dd0580ce4.

- [x] Quantify copied upstream code and distinguish it from existing integration.
- [x] Review canonicalization, BBS, context validation and API changes for concrete defects.
- [x] Independently challenge canonicalizer findings with one adversarial reviewer.
- [x] Run focused verification in an isolated scratch checkout.
- [x] Report findings, scope judgment and limits of verification.

Decisions: review only; no implementation changes or GitHub comments. Use a scratch archive under /private/tmp, preserving the current workspace and its lessons edits. Compare against the exact upstream v3.5.1 source rather than accepting the PR description as evidence.

## Review results

### Duplication and scope

Compared the fork against the exact upstream v3.5.1 `Libraries/dotNetRdf.Core/Core/RdfCanonicalizer.cs`: upstream 450 lines, fork 540 lines, 429 aligned lines unchanged, 21 upstream lines removed/replaced, 111 fork lines added/replaced (counts include comments and whitespace). One complete canonicalization class is vendored, plus an 18-line formatter subclass; JSON-LD processing, parsing and RDF storage remain dotNetRDF. Existing loss-audit and skolemization integration predates this PR.

The fork corrects hash-map removal, already-issued identifier detection, duplicate self-reference quads and non-ASCII predicate hashing. Additional changes implement work/depth limits, first-degree caching, NetCrypto hashing and faster blank-label formatting. Private upstream methods prevent a small override. A differential corpus and an upstream-deviation canary provide a reasoned removal path. The upstream issue #917 remains open and its report/comment are from this repository's owner, not independent maintainer confirmation.

Scope judgment: the bounded fork has a real correctness/interop justification, but need not be bundled with direction support. Prefer separately reviewable direction support, BBS lifecycle corrections, and canonicalizer fork. Move the new KnownContexts policy and unrelated constructor changes into their own changes. Do not treat the PR's size alone as a defect or assume every bundled fix is required for #40/#43.

### Confirmed findings

1. **KnownContexts permits holder-added nested contexts.** `src/DataProofsDotnet.Core/DataIntegrity/DataIntegrityProofPipeline.cs:364` inspects only the root context. Signed a real eddsa-rdfc credential using the V2 root context with subject `name: Alice`; without re-signing, added a subject context mapping `nickname` to `https://schema.org/name` and renamed `name` to `nickname`. Both the proof and document still verify with `KnownContexts = [V2]`. This bypasses the new context-policy control, not the signature. W3C VC Data Integrity 1.0 section 4.6 explicitly checks subtree contexts. Validate the verified document's nested contexts with appropriate JSON-LD semantics or remove/defer this API until complete. Independent adversarial reviewer agreed with this bounded impact.
2. **New base-proof parser rejects proofs accepted by issuance.** `src/DataProofsDotnet.Rdfc/Internal/Bbs2023ProofValue.cs:116` newly requires a 32-byte HMAC key, but `CreateBaseProofAsync` passes arbitrary key lengths into Transform at `Bbs2023Cryptosuite.cs:158`. With the W3C wind document, a 16-byte key successfully issues a proof; DeriveProof immediately rejects it as malformed, with the 32-byte-key requirement in its inner exception. A 32-byte control issues, derives and verifies. Validate key length at creation before returning an unusable credential.

### Verification and limits

- 179 original focused tests passed, none skipped: canonicalization/deviation/differential, direction, BBS conformance and hardening (native BBS available).
- Three added scratch probes: two fail the intended contract (nested context refusal and short-key issuance refusal); one passes and demonstrates the 32-byte successful lifecycle versus the 16-byte issuance/derivation inconsistency.
- Probe source: `/private/tmp/dataproofs-pr42-review/tests/DataProofsDotnet.Rdfc.Tests/Pr42ReviewTests.cs`; final log: `/private/tmp/dataproofs-pr42-repro-final.log`.
- Adversarial review refuted a suspected blank-node formatter collision: dotNetRDF cleans those input labels and the crafted case was refused. No additional confirmed canonicalizer blocker. The already documented UTF-16/code-point ordering deviation was not counted as a new regression.
- Tests ran from the exact-head scratch archive with local socket access, single-process MSBuild and shared compilation disabled. NuGet vulnerability audit was disabled for this offline review because its network lookup failed; this was not a dependency-security audit. Archive builds emitted expected SourceLink warnings due to lacking `.git`.
- This is a focused PR review, not a full-solution test or a proof that no other defects exist. No source changes, merges or GitHub comments were made in the repository.
