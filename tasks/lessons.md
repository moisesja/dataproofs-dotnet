# Lessons

Self-improvement log (AGENTS.md §3). After any user correction, record the pattern and a
rule that prevents recurrence.

## 2026-06-16 — Always get plan approval before implementing (issue #10)

**Mistake:** On a non-trivial task (issue #10 fix + v1.0.1 bump), I went straight from
research into editing source/tests/version files without presenting a plan for approval.
The user stopped me mid-edit and was rightly angry.

**Why it happened:** I let AGENTS.md §6 ("Autonomous Bug Fixing — just fix it, don't ask
for hand-holding") override §1 ("Plan Mode Fault — enter plan mode for ANY non-trivial
task") and the Task Management rule "Verify Plan: Check in before starting implementation."

**The rule for myself:**
- §6 means *don't ask how to fix it / don't need babysitting on mechanics*. It does NOT
  override §1. Plan approval is still required for non-trivial work.
- A task is non-trivial (→ plan + explicit approval BEFORE any edit) when it is 3+ steps,
  touches multiple files, changes a public API or version, or **reverses a prior decision**
  (especially a security one). Issue #10 was all of these.
- The sequence is: research read-only → present plan → WAIT for "yes" → implement.
  Creating a branch, a todo file, or any source/test edit all count as "implement."
- When two instructions appear to conflict, the more conservative/process-protective one
  wins unless the user has said otherwise in this session.

## 2026-06-22 — A side-channel fix must close every channel, not just the headline one (issue #12)

**Mistake:** Fixing the issue-#12 recipient-key enumeration *timing* oracle, I implemented the
constant-work (decoy ECDH) half and shipped it as "done" — but left the **exception
type/message** distinguishable (held key → AEAD-stage `MalformedJoseException`/"AEAD decryption
failed"; unheld key → unwrap-stage `JoseCryptoException`/"AES-KW unwrap failed"). The
adversarial review caught it: timing was equal, but a length-corrupted captured envelope still
enumerated possession through the exception channel.

**Why it happened:** I fixated on the issue *title* ("timing side-channel") and under-weighted
the issue's own "Recommended fix" list, whose **"Uniform failure"** bullet was as load-bearing
as the constant-work bullet. I treated the timing fix as the whole fix.

**The rule for myself:**
- For any information-disclosure / side-channel fix, enumerate **all** observable channels —
  **time, exception type, exception message, inner exception, status code, log lines, response
  shape** — and make held/unheld (or secret/non-secret) indistinguishable across **every** one.
  A constant-time fix with a leaky exception is not a fix.
- Read the issue's "recommended fix" as a checklist; implement **every** clause, not just the
  one matching the title.
- Always run the adversarial subagent on a security fix *before* declaring done — and when it
  finds a residual in the same threat class, treat it as in-scope, not a follow-up.
- Uniform-failure pattern: one exception type, one fixed message, no secret-derived detail
  (kid/stage), **no inner cause** (the inner can re-leak the stage). See
  `JweParser.DecryptFailureMessage`.

## 2026-07-27 — A regression test must not assert a spec-nonconformant fixture as "valid" (issue #15, PR #16)

**Mistake:** Fixing issue #15, I added `JwsJson_MatchingStringKidInBothHeaders_...` that built a
JWS carrying `kid` in **both** the protected and unprotected headers and asserted it as a valid,
verifying input. RFC 7515 §5.2 step 4 / §7.2.1 require the two header objects' parameter-name sets
to be **disjoint** — a duplicate name is invalid *even when the values match*. The test locked a
known parser leniency (the issue #10 "both must match" agreement check) in as correct behavior, in
a project whose stated goal is JOSE conformance. The reviewer (repo owner) declined to approve over
exactly this.

**Why it happened:** I reached for the nearest fixture that exercised "a valid string unprotected
kid still verifies" (put it in both headers, matching) without checking the fixture itself against
the spec — and without noticing the regression I actually wanted was **already** covered by the
existing issue #10 disjoint-shape test. I treated "the parser accepts it" as "the input is valid."

**The rule for myself:**
- Before asserting any constructed protocol fixture is *valid*, check the **fixture** against the
  normative spec, not just the code path. "The parser accepts it" ≠ "it is spec-conformant" — a
  lenient parser will happily verify an invalid message, and a test that pins that as correct
  cements the nonconformance.
- Prefer the **minimal spec-conformant** shape that exercises the behavior under test (here: `kid`
  in the unprotected header only). If an existing test already covers that shape, don't add a
  redundant — and possibly nonconformant — variant.
- When a fix reveals that the *parser itself* is lenient past the spec (accepting both-present
  matching `kid`), that is a **separate conformance decision** — surface it explicitly (it may
  reverse a prior decision, e.g. issue #10), don't silently bake it into a new test or silently
  "fix" it in an unrelated PR.
- Keep unrelated build-unblock changes (the AngleSharp `NU1902` floor-lift) in their **own commit**
  so independent changes carry independent rollback decisions — a reviewer should be able to revert
  one without the other.

## 2026-08-04 — Reading the plan-approval lesson is not the same as applying it (issue #17, PR #18)

**Mistake:** Given "Address issue #17. I'd like to deploy this fix as version 1.2.0", I went from
reading the issue straight to branching, editing source and tests, re-pinning a frozen vector,
bumping the version, committing, pushing, and opening PR #18 — with no plan presented and no
approval. The user stopped me just before the merge/tag. This is the **same** violation as
2026-06-16 (issue #10), in a repo where that lesson was already written down.

**Why it happened — and this is the part that matters:** I *did* read `tasks/lessons.md` early in
this session, including the 2026-06-16 entry and its explicit line "Creating a branch, a todo file,
or any source/test edit all count as 'implement.'" I read it as background and never converted it
into a gate on my own next action. Two things let that happen:
1. I treated the request's phrasing — a fix *and* a named release version — as pre-authorization
   for the entire arc, when a version bump plus a publish is the strongest possible signal that a
   task is non-trivial and needs sign-off.
2. Writing `tasks/todo-2026-08-04-issue-17.md` *felt* like satisfying "Plan First", so the
   check-in step got silently absorbed into it. AGENTS.md lists "Plan First" and "Verify Plan" as
   two separate steps precisely because writing a plan down is not the same as getting a yes.

**The rule for myself:**
- Reviewing lessons at session start is worthless unless each one is checked against **this task**
  before the first tool call that writes anything. Concretely: before the first Write/Edit/`git
  checkout -b`/`git commit`, stop and answer "does the 2026-06-16 plan-approval lesson apply here?"
  If the answer is yes or unclear, enter plan mode and call ExitPlanMode. No exceptions.
- A request that names a **version number, a release, a deploy, or a publish** is non-trivial by
  definition. Fix-and-ship is authorization for the **goal**, never a waiver of the approval step
  for the **means** — and the release half in particular ends in an irreversible public artifact.
- Writing `tasks/todo-*.md` is not the check-in. The check-in is an explicit "yes" from the user.
  The todo file is for tracking work that has **already** been approved.
- When I catch myself thinking "this is what they obviously want, just do it", that is the exact
  condition AGENTS.md §6 does *not* cover. §6 is about not needing hand-holding on **mechanics**.

## 2026-08-05 — Re-review the fix, not just the bug; and check the issue's premise against the spec (issue #25)

**Three things worth keeping from this one. No user correction was needed, but two of them were
caught only because something re-checked my work.**

**1. The issue's proposed fix had no spec basis, and asking "what does the spec say?" changed the
design.** Issue #25's primary proposal was to move `kid` to the unprotected header unconditionally.
Reading RFC 7515 §4.1.4/§6 showed both placements are conformant — §6 explicitly exempts `kid` from
integrity protection *when the only trust input is a key* — and that DIDComm pins the shape by
example (Appendix C.2) and by implementation, not by any MUST. So an unconditional move would have
changed emitted bytes for every consumer with no spec requiring it. The rule: **when an issue
proposes a fix, verify its normative premise before implementing it.** A well-argued issue from the
repo owner is still a hypothesis. Quote the normative text in the plan so the reasoning is
reviewable.

**2. Verifying against the *real* counterparty source found a blocker the issue missed.** The issue
attributed didcomm-python's rejection to the `kid`. Reading `didcomm/core/sign.py` at the exact
cited version showed `validate_jws` runs on the **raw** dict and requires a `signatures` array —
so our Flattened single-signer output would still have been rejected after the `kid` fix, leaving
interop at 1-of-2 and the issue's actual goal unmet. The rule: **for an interop fix, read the
counterparty's source at the version named in the report and trace the specific code path, rather
than trusting the reporter's attribution of the error.** "Both implementations reject us" is the
observation; *why* is a claim to verify.

**3. A security fix needs its own adversarial pass — the fix is new code too.** Pass 1 found four
real defects, including one that disproved a confident security claim I had written into the
CHANGELOG ("denial of service, not forgery" — false whenever the caller's key resolver is not
injective, e.g. one DID doc listing a key under two verification-method ids). Pass 2, reviewing
*the fixes*, found that my fix for the null-`kid` crash had **reintroduced the same bug class** —
`TryGetProperty` throws `InvalidOperationException` on a non-object root, escaping the documented
exception contract on three entry points, and strictly easier to reach than the bug it replaced.
The full suite was green the whole time because no test covered a non-object protected-header root.
The rules:
- **Send the adversarial reviewer back over its own findings' fixes.** One pass reviews the change;
  it does not review the repair. Budget for two.
- **A green suite after a security fix means nothing if the suite never covered the input class.**
  Ask "what input would distinguish the fixed code from the broken code?" and confirm a test
  actually fails when the fix is reverted — the reviewer checked exactly this for all five new
  tests, and that check is what makes them worth having.
- **When hardening an exception contract, enumerate the exception *types* the API can emit, not
  just the one in the report.** `JsonElement` throws `InvalidOperationException`, not
  `JsonException`, for non-object roots and invalid UTF-8 member names — a `catch (JsonException)`
  looked complete and was not. This is the 2026-06-22 "close every channel" lesson in a new
  costume: I fixed the reported channel (`null` kid) and opened an adjacent one.
- **Reordering validation ahead of parsing changes which errors fire first.** Any check moved
  *before* a deserialize inherits none of deserialize's error handling.

## 2026-08-04 — A control that only exists in a comment is not a control (issue #20)

**Mistake:** `RELEASING.md`, the `environment: nuget-release` comment in `publish.yml`, PR #18, and
`tasks/todo-2026-08-04-issue-17.md` all stated that a tag push waits for release approval. None of
them had ever checked. The `nuget-release` environment had `protection_rules: []` and
`can_admins_bypass: true` from the day it was created, so v1.2.0 went from tag to published on
NuGet.org in 55 seconds with no human stop — on the one path in this repo that cannot be undone.
Worse, the wording was confidently *ordered* ("build/test/ac-11 gates, **then** waits for
approval"), which is not even how environment protection works: it gates the whole job, before the
checkout. A detailed, plausible description of a control read as evidence that the control existed.

**The rule for myself:**
- When I write, copy, or repeat a claim about **platform behavior I did not configure in this
  change** — an environment gate, a branch protection, a required check, a trusted-publishing
  policy, a webhook — verify it against the platform's API in the same change, or write it as an
  open TODO. `gh api .../environments/<name>` takes one call. Repo settings live outside the
  diff, so nothing in code review can catch a stale claim about them.
- Prose inherited from a sibling repo (`tasks/research/conventions.md` carried this same "gated
  behind a reviewer-approved environment" line) describes *that* repo's intent, not this repo's
  configuration. Convention text is a template to verify, never a statement of fact.
- Before declaring an irreversible step "gated", answer concretely: *what stops it, where does that
  thing live, and what does the API return right now?* If any answer is "the docs say so", it is
  not gated.
- Docs that turn out to be false get a dated correction in place, not a silent rewrite — the
  earlier claim is what someone acted on, so the record has to show it was wrong.

## 2026-08-05 — Compatibility is a policy constraint, not an automatic review veto (PR #26)

**Mistake:** I made removal of the two-argument `JwsSigner` constructor the lead blocking finding
on PR #26. The binary-compatibility analysis was technically correct, but the repository owner
does not require binary compatibility for this release and explicitly accepts updating downstream
systems. I silently promoted a conventional library-maintenance preference into an acceptance
criterion the owner had not set.

**The rule for myself:**
- Still identify a binary/source/wire compatibility break precisely; reviewers need the fact.
- Before using it to request changes, check the repository's stated release policy and the owner's
  expressed migration tolerance. Compatibility impact is evidence, not automatically a veto.
- When downstream systems are owned and can move in lockstep, classify an intentional break as a
  migration/release note unless the user or project explicitly requires compatibility.
- A waived compatibility constraint does not waive independent correctness or security findings.

## 2026-10-26 — A CHANGELOG claim that names entry points is one claim per entry point (issue #28)

**What happened:** The 1.3.0 CHANGELOG stated that a protected header with a non-UTF-8 member name
"now route[s] through the documented contract on all three entry points — `JwsParser.Parse`,
`JwsParser.ParseCompact`, and `VcJose.VerifyCredential`". Only `Parse` did. The rejection on the
JSON path was a side effect of the member-name enumeration added for the #19 disjointness check,
and the compact path skips that enumeration on purpose. No test exercised invalid UTF-8 on *any*
of the three, and an invalid extension *value* passed on all of them. A downstream adversarial
review (credentials-dotnet#20) found it, not ours. Tracing the root cause then found the same
omission in four more decoders, two of them reachable before any signature check.

**Why it happened:** The 1.3.0 adversarial pass observed the JSON path rejecting the input; I wrote
down what I inferred ("all three"), and the suite stayed green because nothing covered the input
class. This is the 2026-08-05 lesson ("a green suite means nothing if the suite never covered the
input class") recurring as a *documentation* claim rather than a fix.

**The rule for myself:**
- A CHANGELOG or doc sentence that names N entry points is N claims. Each needs a test on the exact
  input class the sentence describes, or the sentence names only the entry points that have one.
- When a rejection is observed, find *which line* rejects it and whether every named path executes
  that line. A rejection that is a side effect of an unrelated check is not a control, and the
  paths that skip the check for performance are the ones to test.
- An input-validation requirement stated in an RFC (here RFC 7515 §5.2 step 3) maps to an explicit
  check with its own test, never to "the parser happens to throw". Before declaring an input class
  closed, grep the sibling decoders for the same decode→parse shape; this time four had it.

## 2026-10-26 — Spike the toolchain's behaviour before designing around it (issue #27)

**What happened:** The first design draft for the native-AOT migration rested on four assumptions,
and a fifteen-minute scratch project in the scratchpad, built before the plan was written, showed
three of them wrong and the fourth incomplete:
1. A `JsonSerializerContext` bound to a `JsonSerializerOptions` **locks** that instance's resolver
   chain — the planned "bind the context, then add the JIT reflection fallback" order throws.
2. The `JsonSerializer.IsReflectionEnabledByDefault` guard does **not** silence the Roslyn trim/AOT
   analyzers; the ASP.NET Core `[UnconditionalSuppressMessage]`-with-justification pattern is required.
3. The .NET 10 source generator models `init`-only members as **constructor parameters**: an
   `init`-only `[JsonExtensionData]` bag throws at first use, and an `init`-only member with an
   initializer comes back `null` when absent from the payload. That forced a public-API change
   (`init` → `set` on two `DataIntegrityProof` members) that belonged in the plan for the owner's
   approval, not in a mid-implementation surprise — and a regression test for a behaviour (`Type`
   defaulting) that *serialization* byte-identity tests would never have caught.
4. An internal `[JsonConverter]` type blocks every downstream consumer's source generator
   (SYSLIB1220), which turned "no public API change" into one deliberately public type.

**The rule for myself:**
- When a design depends on how a toolchain or library behaves — a source generator, an analyzer, a
  trimmer feature switch, a serializer's constructor-selection rules — build a scratch project and
  **observe** it before writing the plan. Recalled documentation is a hypothesis; compiler and
  runtime output are facts. Budget the spike; it is cheaper than one re-plan and far cheaper than
  an approved plan that later needs a public-API amendment.
- For System.Text.Json source generation specifically: inspect the generated code
  (`EmitCompilerGeneratedFiles=true`) for every model shape — `init`, `required`, initializers,
  extension data, private setters, record copy constructors — and test a **deserialization with a
  member absent**. Serialization byte identity says nothing about deserialization defaults.
- State the version/release assumption as the **first** decision in a plan. The owner's one-line
  rejection ("Version is still 1.4.0. We haven't deployed.") corrected an assumption I had reasoned
  about at length; putting it first makes it the first thing the owner can strike.

**Addendum, same day — "analyzer-clean" is a claim about annotated code only.** With all six
packages building warning-free under `IsAotCompatible`, the first reflection-disabled run of the new
`tasks/aot-smoke` still failed: NetCid's `JcsCanonicalizer.Canonicalize(JsonNode)` serializes through
reflection internally, and NetCid carries no annotations, so every JCS proof with `@context` would
have failed to verify in an AOT host. The rule: **zero trim/AOT warnings from the packages' own build
proves nothing about unannotated dependencies.** Before claiming AOT support, run every public path
with `JsonSerializerIsReflectionEnabledByDefault=false` (cheap, no native toolchain) and as a native
binary, and turn each hidden-reflection dependency API found into a `BannedSymbols.txt` entry with
the reason, so the compile step guards what the analyzers cannot.

**Second addendum, after the adversarial review — and do not write a gate that ignores the evidence.**
The ILCompiler's whole-program analysis *did* report the NetCid reflection, as a NetCid IL2026/IL3050
in the publish log. My first `ac-12` scan treated every third-party IL warning as "informational" and
failed only on DataProofs-attributed ones, so it would have passed the bug; only the runtime leg
caught it, and only because that path happened to be exercised. I also wrote "no analyzer could see
it" into the CHANGELOG, which the same log disproved. The rules:
- A gate's allowlist is per finding, not per category. "Third-party warnings are expected" was a
  category; the fix is a reviewed list of exact warnings (`known-il-warnings.txt`), each with the
  reason it is unreachable, and failure on anything else.
- Hidden problems in a dependency surface as *that dependency's* diagnostics. A filter that discards
  diagnostics by attribution discards exactly those.
- A scan needs negative controls for the input classes it must reject (unknown dependency warning,
  empty log, a publish where the compiler did not run), not just a regex control.

## 2026-10-27 — Escapes typed into a tool call are not escapes on disk; spike with production options (issue #30)

**No user correction; both were caught by verification, one by my own test matrix and one by the
adversarial reviewer.**

**1. The over-rejection guards tested nothing, and every guard was green.** I wrote
`Issue30ContractEscapeTests.cs` with guards spelled `@"\uD83D\uDE00"`, `@"\u00e9"`, `@"k\u0031"`.
The file on disk held the literal emoji, `é` and `k1`: the Write tool (and the reviewer's Edit
tool) decoded every *valid* `\uXXXX` sequence in its input before it reached the file. A Bash
heredoc passed the same text through intact. Only the lone surrogates survived, because they can't
be decoded. The negative tests were therefore real and the positive ones hollow. A mutant that
rejected *every* surrogate escape passed 1193 of 1194 Jose tests, which left the CHANGELOG's
"a surrogate pair included" claim untested. The same decoding reached the plan file. The reviewer
caught it with a raw-byte dump.

**The rule for myself:**
- Never type a JSON or C# `\uXXXX` escape that a test depends on. Build it at run time from its code
  unit (`@"\u" + codeUnit.ToString("X4")`): the source then holds nothing a tool can rewrite. The
  same goes for any byte-exact fixture (escapes, BOMs, control characters).
- After writing a file whose meaning depends on exact characters, check the bytes on disk with
  `grep -o '\\u[0-9A-Fa-f]\{4\}'`, `od`, or a non-ASCII grep before trusting a green run.
- A guard ("well-formed input still passes") is only evidence if a mutation that over-rejects makes
  it fail. Run that mutant once per guard family; this time it took the failing guards from 1 to 23.

**2. The spike used default options; production used strict ones.** My System.Text.Json spike
parsed with default `JsonDocumentOptions`. The production call sites use
`AllowDuplicateProperties = false`, whose duplicate check transcodes every member name inside
`JsonDocument.Parse` itself and throws `InvalidOperationException`. So the approved design, which
scanned the JWS/JWE envelope *after* the parse, was wrong for member names. The 64 failing test
rows exposed it on the first run, and the check moved ahead of the parse
(`JoseJson.ParseStrictDocument`). The rule: **a spike must call the API with the exact options the
production call site passes.** The 2026-10-26 "spike first" lesson is only as good as the fidelity
of the spike.

## 2026-10-27 — Validate the final shape, not only its ingredients (PR #35 review)

The review found two gaps after individually validating a document and proof configuration:
- A depth-64 legacy JCS configuration became depth 65 when nested under `document.proof`, leaking
  `JsonException`. Boundary tests must cover transformations that add levels, with both the last
  successful depth and the first rejected depth. Keep transformation exception mapping outside signer calls.
- An extension named `proofValue` was unique while the typed field was omitted, but signing populated
  that field and emitted a duplicate. Reserve modeled names using serialization metadata regardless of
  their current values; test omitted fields as well as populated ones. Check valid case-distinct and
  nested extensions to avoid unnecessarily narrowing the extension namespace.

A green input-validation matrix does not prove later composition preserves the checked invariants.
