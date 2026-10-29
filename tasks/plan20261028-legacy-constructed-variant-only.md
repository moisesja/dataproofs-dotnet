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
- **A new three-argument constructor overload on both legacy suites.** The existing
  two-parameter constructors keep their signatures, so code compiled against 1.5.0 still binds
  (binary compatible). Calls with zero to two arguments still bind to the old constructor.
- **In `ConstructedVariantOnly`, `VerifyProof` tries only the variant passed at construction.** An
  RDFC data-loss failure is then reported as `DATA_LOSS_DETECTION_ERROR`, as in the RDFC suites.
  This removes the dual-variant code ambiguity listed under 1.5.0's Known limitations. `Both`
  keeps its existing result codes.
- **Release:** additive public API, so this is a minor release (1.6.0) under RELEASING.md. The
  default behavior and emitted bytes are unchanged.

## Steps

- [ ] Enum and constructor overloads; `LegacyCryptosuiteBase` takes the mode
- [ ] `PublicAPI.Unshipped.txt`; XML docs (suite remarks, `LegacyCanonicalization` remarks)
- [ ] Tests in `VariantIsolationTests`:
  - strict suites reject the other variant and accept their own;
  - strict RDFC reports data loss;
  - the default is unchanged;
  - binary compatibility of the old constructors.
- [ ] Sample (FR-21: every public member appears), PRD FR-4, CHANGELOG [Unreleased]
- [ ] Build (warnings as errors), full tests
- [ ] Adversarial review
- [ ] Commit, push, open a PR

## Results

(filled in as work completes)
