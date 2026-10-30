# Plan — respond to the PR #39 review (5707343258)

Branch: `feat/legacy-constructed-variant-only`, PR #39. Review: https://github.com/moisesja/dataproofs-dotnet/pull/39#pullrequestreview-5707343258

## Owner intent

"See if this review is accurate. If so, thoroughly address it." The session runs unattended, so the
decisions below are recorded for the owner to strike rather than approved in advance.

## Is the review accurate?

- **P2, activation regression: accurate.** `ActivatorUtilities.CreateFactory` and
  `ActivatorUtilities.CreateInstance` (with a provider that does not implement
  `IServiceProviderIsService`) enumerate the public constructors and throw
  `InvalidOperationException` ("Multiple constructors accepting all given argument types") when
  more than one accepts the supplied argument types. With two public constructors whose parameters
  are all optional or absent, both accept zero arguments and both accept one `LegacyCanonicalization`.
  Confirmed by running the new `ActivationCompatibilityTests` against c9e0a16 before the fix (10 of 15
  red: 8 with that message, 2 pinning the migration note) and by the reviewer's own probe in
  `/private/tmp/pr39-activation`. Microsoft DI registration by type
  (`AddSingleton(type)`) was never affected, as the review says.
- **Commit hygiene: accurate.** c9e0a16 "PR plans" adds four review logs for PR #37, which this PR
  does not touch.
- **Everything else** (test counts, CI, the `JsonLdDataLossException` base type, no strict-mode bypass)
  matches what is on disk.

## Decisions

1. **One public constructor per suite, with a third optional parameter:**
   `(LegacyCanonicalization canonicalization = Jcs, IRdfCanonicalizer? rdfCanonicalizer = null,
   LegacyVariantVerification verification = Both)`. The two-parameter constructor is removed.
   - Every default-filling activation path (`ActivatorUtilities`, Microsoft DI) behaves as in 1.5.0,
     because there is again exactly one public constructor and every parameter has a default. Proven
     by `ActivationCompatibilityTests`. Exact-arity reflection (`Activator.CreateInstance` with the
     1.5.0 two-argument list, `GetConstructor` with two types) fails like a compiled `new` does; the
     migration note covers it and a test pins it.
   - Every 1.5.0 call shape still compiles and binds (source-compatible). zcap-dotnet calls
     `new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Rdfc, _rdfCanonicalizer)`.
   - It is **not binary-compatible**: an assembly compiled against 1.5.0 throws
     `MissingMethodException` on the two-parameter constructor until it is rebuilt. `RELEASING.md`
     ("Versioning policy") puts binary compatibility out of scope and names this exact pattern, and
     1.3.0 shipped the `JwsSigner` constructor the same way with a migration note. The CHANGELOG
     carries the same note here. `tasks/lessons.md` (2026-08-05) records the owner's position.
   - **Alternative considered, not taken:** the review's static factory with a private constructor
     (`Suite.Create(canonicalization, verification, rdfCanonicalizer)`) keeps binary compatibility as
     well, at the cost of two construction idioms for one type and a shape chosen for a constraint the
     project has waived. If the owner wants binary compatibility for 1.6.0 after all, that is the
     change to make; the tests in `ActivationCompatibilityTests` apply unchanged.
2. **Executable regression tests** for the activation paths the review listed, on both suites:
   `CreateFactory` with no argument types, `CreateFactory` with `LegacyCanonicalization`,
   `CreateInstance` with a provider that is not `IServiceProviderIsService`, `AddSingleton(type)`,
   `Activator.CreateInstance` with the 1.5.0 arguments, and a check that the public constructor set is
   one constructor whose every parameter has a default. The old `TwoParameterConstructor_KeepsItsSignature`
   is replaced, since it only proved a constructor existed.
3. **Commit hygiene.** c9e0a16 is dropped from this branch (it was the tip; `--force-with-lease`).
   The four PR #37 review logs move to their own branch and PR. The review log for this PR
   (`tasks/plan20261029-pr39-review.md`) and this response plan are committed here, with a
   descriptive subject, because they are about this PR.
4. **No version bump** in this PR. `DataProofsVersion` stays 1.5.0 (published); the bump is a release
   step for the owner, as for 1.4.0 and 1.5.0.

## Steps

- [x] Add `ActivationCompatibilityTests`; run against c9e0a16 and record the failures
- [x] Single constructor in both suites; `PublicAPI.Unshipped.txt`; XML docs
- [x] Update `ConstructedVariantOnlyTests`; sample comment; CHANGELOG (Added, migration note); PRD/README wording check
- [x] Dated correction in `tasks/plan20261028-legacy-constructed-variant-only.md`
- [x] Binary-compatibility probe: consumer compiled against 1.5.0, run against the new assembly (expect `MissingMethodException` on `new`, success on every activation path)
- [x] Build with warnings as errors; full test run; samples-coverage tool; legacy sample
- [x] Adversarial review of the fix
- [x] `tasks/lessons.md`
- [x] Rewrite history (drop c9e0a16), commit, push with lease; docs branch and PR for the PR #37 logs; update the PR #39 body; reply to the review

## Results

- **Review accuracy:** the P2 is real. Against c9e0a16, 10 of the 15 `ActivationCompatibilityTests`
  cases fail: 8 with "Multiple constructors accepting all given argument types" (`CreateFactory` with
  no argument types and with `LegacyCanonicalization`, `CreateInstance` with a provider that is not
  `IServiceProviderIsService`, and the one-public-constructor check, on both suites) and 2 because the
  1.5.0 `Activator` arity still bound there. The commit-hygiene point is also accurate.
- **Fix:** one public constructor per suite, three optional parameters. `LegacyCryptosuiteBase` now
  also refuses an undefined `LegacyCanonicalization` value (adversarial finding 1, below).
- **Build:** Release, warnings as errors, clean, PublicAPI analyzers included.
- **Tests:** 2,893 pass across the solution. Legacy has 277, 33 of them new: 18 in
  `ConstructedVariantOnlyTests` (incl. the two undefined-enum theories) and 15 in
  `ActivationCompatibilityTests`.
- **Probe** (consumer compiled against the published 1.5.0 package, run against each assembly;
  `scratchpad/compat-probe`):

  | Probe | 1.5.0 | c9e0a16 (two ctors) | this fix |
  | --- | --- | --- | --- |
  | compiled `new Suite()` / `(Rdfc)` / `(Rdfc, canonicalizer)` (6) | pass | pass | `MissingMethodException` (migration note) |
  | `ActivatorUtilities.CreateFactory(type, [])` | pass | throws | pass |
  | `ActivatorUtilities.CreateFactory(type, [LegacyCanonicalization])` | pass | throws | pass |
  | `ActivatorUtilities.CreateInstance(provider without IsService, type)` | pass | throws | pass |
  | `new ServiceCollection().AddSingleton(type)` | pass | pass | pass |
  | `Activator.CreateInstance(type, Rdfc, null)` | pass | pass | `MissingMethodException` (migration note) |
  | public constructors == 1 | yes | no (2) | yes |

- **Gates:** samples-coverage exit 0 (551 members, 549 covered, 2 allowlisted); the legacy sample
  exits 0; api-surface-scan CLEAN, dependency-hygiene CLEAN and AotSmoke JIT emit/verify exit 0 (run
  by the adversarial reviewer).
- **Adversarial review of the fix** (one reviewer; probes in `scratchpad/probes`, mutants in
  `scratchpad/adv-copy`): no blocking finding and no strict-mode bypass. `CreateInstance<T>`,
  `GetServiceOrCreateInstance`, keyed/transient/scoped/interface registrations, `ValidateOnBuild`,
  `JsonSerializer`, `BindingFlags.OptionalParamBinding`: identical to 1.5.0. F# (13 shapes) and VB
  (14 shapes, including the omitted middle argument) compile with warnings as errors and bind as
  expected. Configuration binding of the enum: "ConstructedVariantOnly"/"1" strict, "2"/"-1" refused,
  missing key yields `Both`. Mutations: re-added two-parameter constructor 10 red; exact c9e0a16
  sources 10 red (the PublicAPI analyzer does **not** catch a non-optional overload; only the tests
  do); defaults removed 10 red plus CS7036 on recompile; strict fall-through 6 red and the sample
  exits 1; undefined-value guard removed 2 red; default flipped 4 red.
  Findings and dispositions: (1) undefined `LegacyCanonicalization` acted as JCS, so a misconfigured
  "RDFC only" verifier would accept JCS proofs: guard, test, XML doc and CHANGELOG added. (2) the
  CHANGELOG claimed a test for `CreateInstance` with `IServiceProviderIsService` that did not exist,
  and "the ActivatorUtilities paths throw" was over-broad (with the real container `CreateInstance`
  picks the longest satisfiable constructor): test added, CHANGELOG and inline comment narrowed.
  (3) "8 of 13" was 10 of 15: corrected. (4) "every reflection-based path behaves as in 1.5.0" was
  false for exact-arity reflection: reworded, and the older plan's "runs unchanged" marked superseded.
  (5) `OptionalParamBinding` clause added to the migration note. (6) PRD "(1.6.0)" label changed to
  "(PR #39)", the PRD's own convention. (7) `Both` is the zero value: sentence added to the enum
  remarks and the CHANGELOG. (8) PublicAPI file sorted. (9) analyzer gap recorded here. (10) the
  third parameter's type and default asserted.
- **Open for the owner:** the version bump (1.6.0), and whether binary compatibility should be kept
  after all (Decision 1's alternative).
- **History and PR:** the four PR #37 logs travel on `docs/pr37-review-logs` as PR #41. The
  force-push that would have dropped c9e0a16 from this branch was refused by the session's tool
  permissions, so instead c9e0a16 stays in history and a revert commit on top removes its files, with
  the explanation the review asked for. A fast-forward push then updates the PR. For a clean history
  the owner can squash-merge, or drop c9e0a16 and the revert with an interactive rebase and
  force-push with lease. The PR #39 body is rewritten for the single-constructor design and a reply
  is posted under review 5707343258.
