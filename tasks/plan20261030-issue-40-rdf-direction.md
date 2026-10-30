# Plan — RDFC: carry `@direction` losslessly (issue #40)

Branch: `feat/issue-40-rdf-direction` (from `origin/main` 3fd0115, PR #39 merged). Approved 2026-10-30.

## Owner intent

Since 1.5.0 (#36) the RDFC canonicalizer refuses any JSON-LD input that uses `@direction`, because
dotNetRDF's default JSON-LD→RDF conversion drops the base direction, so ≤1.4 signed identical bytes
for `ltr` and `rtl`. The refusal makes the W3C VCDM 2.0 test suite's four "name/description with
language and direction" cases fail at issuance for credentials-dotnet. Issue #40 asked for an opt-in
`rdfDirection: i18n-datatype` option with the refusal kept as the default.

## Premise check (2026-10-30)

The issue states that signing direction losslessly goes beyond the spec and is not verifiable by
implementations using the JSON-LD default. Checked against the upstream sources: the reference Data
Integrity stack already canonicalizes with `rdfDirection: 'i18n-datatype'`:

- `digitalbazaar/jsonld-signatures`, `lib/suites/LinkedDataSignature.js` (`_canonize`);
- `@digitalbazaar/eddsa-rdfc-2022-cryptosuite` and `ecdsa-rdfc-2019-cryptosuite`, `lib/canonize.js`;
- `@digitalbazaar/di-sd-primitives`, `lib/canonicalize.js` (used by `ecdsa-sd-2023` and `bbs-2023`).

`vc-data-integrity` and `vc-di-eddsa` do not mention `rdfDirection`, so it is an unstated profile
parameter, and the de-facto choice is i18n-datatype. A refusing verifier cannot process what those
issuers sign.

## Decisions

- **D0 — Always carry direction; no option.** `JsonLdContextCache.Options()` sets
  `RdfDirection = I18NDatatype`. Nothing is dropped, a flipped direction breaks the signature, the
  bytes match the reference stack, and no public API changes. Accepted 1.5.0 input canonicalizes to
  the same bytes: direction-free documents are unaffected, and every direction-bearing one was
  refused. Proofs ≤1.4 over directional documents verify in neither version. The issue's opt-in
  enum would have required a constructor change and a migration note for no gain in safety; it is
  recorded as an alternative in the approved plan.
- **D1 — Still refused:** `@direction` on a value that is not a string. JSON-LD 1.1 API §8.6 turns
  booleans and numbers into typed literals before the direction step, so the direction would be
  dropped. New message: "uses @direction on a value that is not a string, which the canonical form
  does not carry". The language-tag check keeps running: with the i18n datatype a malformed tag
  would otherwise become a respelled datatype IRI (`en\n` → `#en%0A_ltr`, no dotNetRDF warning).
- **D2 — Not data loss:** `@direction` on a `null` value (the value object produces no RDF, like
  `@language` on one); an explicit `https://www.w3.org/ns/i18n#en_ltr` datatype and the directional
  value object are the same RDF literal (same class as `1` and `1.0`). Invalid direction values and
  `@type` beside `@direction` fail JSON-LD expansion and stay `RdfCanonicalizationException`
  (`PROOF_TRANSFORMATION_ERROR`).
- **D3 — Release:** a capability change with no API change; minor, under `[Unreleased]` with PR #39.
  `Directory.Build.props` stays at 1.5.0 as PR #39 left it. No tag, no publish.

## Steps

- [x] `JsonLdContextCache.Options()` sets `RdfDirection`; remarks
- [x] `JsonLdLossAudit.FindInValueObject` refuses `@direction` only on a non-string value; remarks
- [x] `RdfcDocumentCanonicalizer` remarks
- [x] Tests: `Issue40DirectionTests` (carried shapes, refused shapes, suites, pipeline, bbs-2023,
      jsonld.js byte pin), Legacy RDFC variant, `Issue36DataLossTests` row updated
- [x] README, PRD FR-9, CHANGELOG `[Unreleased]`, RDFC sample
- [x] Build `/warnaserror`, full test suite, ablation, samples-coverage, api-surface-scan
- [x] Differential check against jsonld.js 9.0.0
- [x] Adversarial review; findings recorded (none required a code change)
- [ ] Commit, push, PR `Closes #40`

## Results

- **Tests:** the full solution passes: 2,942 tests, of which 48 are in the new
  `Issue40DirectionTests` and 1 in `ConstructedVariantOnlyTests` (Legacy). The bbs-2023 case ran
  (the native library is present on this host). Every CI gate passes: build with `/warnaserror`,
  `tasks/samples-coverage` (551 members, nothing new), `tasks/api-surface-scan` (clean),
  `DataProofsDotnet.ApiSurface.Tests`. The RDFC sample runs and shows the signed direction and the
  rejected flip.
- **Ablation:** with `RdfDirection` left unset, 22 tests fail (every carried-literal row, the flipped
  and removed-direction tampers for both suites, the pipeline round trips, the bbs-2023 case, the
  remote-context default and the explicit-twin test). With the non-string guard disabled, 7 tests
  fail (number, boolean, double, number in a list, both suites' data-loss case, and the issue-36 row).
  The "change the language" tampers fail under both builds, as expected: the language was already signed.
- **Differential against jsonld.js 9.0.0** (`rdfDirection: 'i18n-datatype'`, `safe: true`, the bundled
  credentials/v2 context; scripts in the session scratchpad `jsonld-diff/`): byte-identical N-Quads
  for every directional value object shape, including the VCDM 2.0 §11.1 `name`/`description`/
  `issuer.name` shapes, direction without language, `en-US` lowercasing, lists and aliases. The
  `credential name ar/rtl` output is pinned in `CanonicalizeJsonLd_DirectionalCredential_MatchesJsonLdJsByteForByte`.
  Three differences, all on the jsonld.js side: (1) it drops a context-level default `@direction`
  whenever a scoped context applies, because `_cloneActiveContext` (`lib/context.js`) copies `@base`,
  `@language` and `@vocab` but not `@direction`, while dotNetRDF follows JSON-LD 1.1 API §5.3.2;
  (2) it emits an identical quad twice when a document spells the same literal as an explicit
  `i18n#` datatype and as a directional string (rdf-canonize does not deduplicate; a dataset is a set);
  (3) it signs a number's direction away silently, which this library refuses. Worth reporting
  upstream; none changes this implementation.
- **Adversarial review** (90 JSON-LD probes, 32 language-tag probes, an 89-fixture mode diff, 10
  bbs-2023 scenarios; probes in the session scratchpad `adversarial/probe/`): no forgery. Every
  direction flip, removal or language change in every position changes the bytes or is refused;
  every issue-36 refusal still holds; direction-free fixtures are byte-identical with the option
  unset. Findings, all pre-existing and fail-closed: (F1) bbs-2023 cannot verify an untampered reveal
  of a document holding an `@list` value, with or without direction (list blank nodes are not
  skolemized); recorded under CHANGELOG known limitations and PRD FR-12; the issue text is drafted
  in the scratchpad (`issue-bbs-list.md`) because filing it was not permitted from this session.
  (F2) A language map under bbs-2023 is refused with the language-tag message rather than the
  skolemization one; recorded in the same places. (F3) A context default `@direction` reaches plain
  strings only (spec-conformant); one sentence added to the canonicalizer remarks. Also noted:
  dotNetRDF's `LanguageTag.IsWellFormed` rejects some valid BCP 47 tags (`x-abc`, `sl-rozaj-biske`,
  `en-US-u-va-posix`), pre-existing strictness.
- **Timing:** the RDFC test project took 14 minutes on one full-solution run while the adversarial
  probes were building and running concurrently; rerun alone it took 7 seconds (675 tests), as before.
