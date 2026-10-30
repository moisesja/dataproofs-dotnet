# Plan — legacy suites: opt-in verification of the constructed variant only

Branch: `feat/legacy-constructed-variant-only` (from `origin/main` 9523a53, release 1.5.0).

## Owner intent

zcap-dotnet's red team found that zcap, which signs only with the legacy RDFC variant, also accepts
JCS-variant proofs. This happens because `LegacyCryptosuiteBase.VerifyProof` always falls back to
the other variant. It is not a forgery path, since JCS signs bytes verbatim, but it is outside
zcap's profile and widens what attacker input reaches.

The owner chose to fix it here, as an option, rather than inside zcap (2026-10-28). zcap adopts it
after a release, and zcap PR #160 does not wait for it.

## Decisions

- **New public enum `LegacyVariantVerification`:**
  - `Both = 0`: the current behavior and the default;
  - `ConstructedVariantOnly = 1`.
- **A new three-argument constructor overload on both legacy suites**, with all parameters
  optional.
  - The existing two-parameter constructors keep their signatures, so code compiled against 1.5.0
    still binds (binary compatible). They lose their default values in source (RS0027).
  - Two-argument calls bind to the old constructor. Calls with zero or one argument bind to the new
    overload, with the same result.
  - The cost of having two constructors: `ActivatorUtilities.CreateFactory` and
    `ActivatorUtilities.CreateInstance` without `IServiceProviderIsService` become ambiguous. This
    is documented in the CHANGELOG. A single constructor would break 1.5.0 binaries instead.
  - **Correction (2026-10-29, PR #39 review 5707343258):** documenting the ambiguity did not fix it.
    Every consumer that activates a suite through `ActivatorUtilities` failed at startup with
    "Multiple constructors accepting all given argument types" (10 of 15 cases in the new
    `ActivationCompatibilityTests` fail against c9e0a16, 8 of them with that message; the other 2 pin
    the migration note below). The two-parameter constructor is
    removed; each suite has one public constructor with three optional parameters. Binary
    compatibility is out of scope under `RELEASING.md`, so the CHANGELOG carries a rebuild note, as
    1.3.0 did for `JwsSigner`. The review's alternative, a static factory with a private constructor,
    would keep binary compatibility too; see `tasks/plan20261029-pr39-response.md` for why it was
    not taken.
- **In `ConstructedVariantOnly`, `VerifyProof` tries only the variant passed at construction.** An
  RDFC data-loss failure is then reported as `DATA_LOSS_DETECTION_ERROR`, as in the RDFC suites.
  This removes the dual-variant code ambiguity listed under 1.5.0's Known limitations. `Both`
  keeps its existing result codes.
- **Release:** additive public API, so this is a minor release (1.6.0) under RELEASING.md. The
  default behavior and emitted bytes are unchanged.

## Steps

- [x] Enum and constructor overloads; `LegacyCryptosuiteBase` takes the mode and rejects undefined values
- [x] `PublicAPI.Unshipped.txt`; XML docs (suite remarks, `LegacyCanonicalization` remarks)
- [x] Tests in the new `ConstructedVariantOnlyTests`:
  - strict suites reject the other variant and accept their own;
  - strict RDFC reports data loss;
  - the default is unchanged;
  - binary compatibility of the old constructors;
  - undefined enum values.
- [x] Sample (FR-21: every public member appears), PRD FR-4, CHANGELOG [Unreleased]
- [x] Build (warnings as errors), full tests
- [x] Adversarial review
- [x] Commit, push, open a PR

## Results

- **Tests:** the full solution passes. Legacy has 262 tests, 18 of them new.
- **Ablation:** with strict mode disabled, all 6 strict-mode tests fail.
- **Sample:** the legacy sample runs. The RDFC-only verifier rejects a JCS proof of the same
  credential, which the `Both` verifier accepts.
- **Adversarial review of b42d291:** no bypass.
  - A strict suite never accepted the other variant across 28 signed cases.
  - `Both` matched 1.5.0 on 1,580 differential results.
  - A consumer compiled against 1.5.0 runs unchanged, and 15 C# call shapes, VB and F# compile.
    (Superseded 2026-10-29: with one constructor, a consumer compiled against 1.5.0 must be
    rebuilt; see the correction under Decisions. The call shapes still compile and bind.)
  - Minor is the right release type.
- **Review findings fixed:**
  1. An undefined `LegacyVariantVerification` value acted as `Both`. It is now rejected, following
     the `JwsSigner` precedent.
  2. The `ActivatorUtilities` ambiguity is documented. (Superseded 2026-10-29: it is removed; see
     the correction under Decisions.)
  3. The old constructors carried a duplicate `<summary>`; it is removed.
  4. This plan was inaccurate; it is corrected here.
- **Not addressed (pre-existing, reported out of scope):**
  - A document with a duplicate key makes `JsonObject.Create` in `BuildJcsSigningInput` throw
    `ArgumentException`. A JCS-first suite then returns "Verification failed unexpectedly" without
    trying RDFC. It fails closed.
