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
- **D1 — Still refused:** `@direction` on a value that is not a string. dotNetRDF (like jsonld.js)
  types booleans and numbers as XSD literals and drops the direction; JSON-LD 1.1 API §8.2.2 step 12
  would apply the i18n datatype to the lexical form instead (correction from the independent review
  of PR #42: the drop is processor behaviour, not the spec's, and the section is §8.2.2). New message: "uses @direction on a value that is not a string, which the canonical form
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

# Round 2 — fix everything the review found, in this PR (approved 2026-10-30)

## Owner intent

After round 1 the owner asked that the findings recorded as "known limitations" and "follow-ups" be
fixed in this PR instead of deferred, and, once the investigation of #43 showed a conformance defect,
chose to fix that here too ("Fix it in this PR"). Lesson recorded in `tasks/lessons.md` (2026-10-30).

## What the investigation found

- bbs-2023 did not interoperate with the reference implementation in either direction. The W3C
  `derivedRevealDocument.json` did not verify here (the test checked the CBOR framing only); a reveal
  made here failed on the reference verifier ("Number of disclosed messages (10) does not equal
  number of selectiveIndexes (6)"). Causes: the base proof signed every N-Quad (spec: non-mandatory
  only); indexes were absolute (spec: relative); the reveal exposed `urn:bnid` skolem IRIs (spec:
  the document as written); the derived label map was keyed by skolem labels and read back as
  `b<int>` (spec: the reveal's `c14n<int>` labels); the HMAC hashed stable labels (spec: c14n labels).
  The last two are why list blank nodes were lost (#43).
- The reference cannot sign a document with an `@list` at all (its expanded-form skolemizer makes the
  list object invalid JSON-LD).
- NetCrypto 1.7.1's BBS provider needs at least one signed message and at least one revealed index,
  so the spec's all-mandatory documents and mandatory-only disclosures cannot be produced here.

## Decisions

- D1 bbs-2023 follows the reference algorithms (messages, indexes, reveal shape, label-map keys, HMAC
  input); CBOR framing unchanged; compact skolemizer kept (#38 stays about what is skolemized).
- D2 A blank node left after skolemization (an `@list`) is refused at creation and derivation. Closes #43.
- D3 Verification does not skolemize; the PR #37 "re-inserted member" vector becomes a plain
  signature failure.
- D4 1.5.0 bbs proofs do not verify with this code and vice versa (they verified nowhere else).
- D5 One public constructor each on `RdfcDocumentCanonicalizer`, `EddsaRdfc2022Cryptosuite`,
  `EcdsaRdfc2019Cryptosuite`, `Bbs2023Cryptosuite`; binary-breaking, source-compatible.
- D6 A skolemized document that no longer canonicalizes is reported as "skolemization would change it".
- D7 Mandatory-only disclosures and all-mandatory documents are refused with messages naming the
  remedy, as a NetCrypto limitation; lifting it needs a NetCrypto change.
- `JsonPointer` unchanged: explicit `_:` ids in a document leave a blank node after skolemization
  and are refused by D2, so the spec's "skip `_:` ids" rule has nothing to act on.

## Results

- Full solution: 2,980 tests green (Rdfc 713, of which 9 in `Bbs2023ConformanceTests` and 29 in
  `RdfcActivationCompatibilityTests`); build with `/warnaserror`; three samples run;
  `tasks/samples-coverage` (547 members, report regenerated) and `tasks/api-surface-scan` clean.
- Conformance: `derivedRevealDocument.json` verifies directly and through the pipeline; the base
  proof's BBS header equals `addHashData.json`; the derived label map and relative indexes equal
  `derivedDisclosureData.json`/`derivedAdjIndexes.json`; the reveal equals `derivedUnsignedReveal.json`.
- Interop, out of band (scratchpad `bbs-ref/script/verify-ours.mjs`, `@digitalbazaar/bbs-2023-cryptosuite`
  2.0.1): our windDoc reveal for `windSelective.json` verifies on the reference verifier; the W3C
  vector verifies there too (sanity).
- Ablations: signing all N-Quads → 7 tests fail (every own-round-trip); reading label-map keys as
  `b<int>` → 8 fail, including the W3C vector; blank-node guard off → both list tests fail.
- Tests adapted: selective pointers in the lifecycle, issue-33 and issue-36 bbs tests moved from
  `/credentialSubject/sails/1` (a mandatory pointer in the W3C set, which made those disclosures
  mandatory-only) to `/credentialSubject/sails/0`; the deleted-`@id` test now expects
  `PROOF_VERIFICATION_ERROR`; the mandatory re-pack test grows the selective set by an unused index.
- Adversarial review of the rework (90+ probes, reference-verifier cross-checks): no forgery.
  Findings and what was done:
  - F1 RDFC-1.0 deviation in dotNetRDF (tied blank nodes owning blank nodes are numbered
    breadth-first; the spec and rdf-canonize go depth-first): confirmed on a six-quad dataset. Owner
    decision: report upstream and document. Filed as dotnetrdf/dotnetrdf#917; CHANGELOG known
    limitation, PRD FR-9, and `RdfCanonicalizationDeviationTests` as a canary that fails once an
    upgrade fixes it. Not a net-did matter: this repo does not reference net-did, and net-did has no
    RDF canonicalization (did:webvh uses JCS).
  - F2 pointers failing open: an empty pointer now selects the whole document and a pointer that
    matches nothing is refused (`JsonPointer`, mapped to `ProofGenerationException`); creation
    validates its mandatory pointers like derivation does (F3).
  - F4 derivation never checked the base proof: it now recomputes the BBS header from the document
    and proof configuration and verifies the signature over the non-mandatory messages before
    deriving; base proofs with a header or HMAC key of the wrong length are malformed.
  - F5 misleading refusals: explicit `_:` identifiers are preserved as skolem ids (shared references
    work; generated labels carry a per-process random part so they cannot collide); a blank node
    identifier used as a plain value is named in the refusal; any failure to canonicalize the
    skolemized copy is "skolemization would change it" (`@nest`, aliased `@id`, top-level `@graph`).
  - F6 derived proof-value parsing: an oversized or textual CBOR component and a proof of impossible
    length are "not a valid bbs-2023 derived proof"; duplicate or negative selective indexes fail
    with their own reason.
  - F7 context substitution: owner decision "in this PR". `ProofVerificationOptions.KnownContexts`
    implements VC Data Integrity 1.0 §4.6 in the Core pipeline, after the proofs (Core tests, sample,
    PublicAPI, PRD FR-3, CHANGELOG). The derived proof no longer carries `@context` (reference parity).
  - F8 many-to-one label map: spec-inherent (RDF entailment), noted only.
  - The independent review of round 1 (another session) corrected the direction rationale: dotNetRDF
    and jsonld.js drop a number's direction; JSON-LD 1.1 API §8.2.2 would apply the i18n datatype.
    Wording fixed in source, tests, PRD, README and CHANGELOG.
- Final state: 3,004 tests green (Rdfc 729, Core 516), four samples run, both gates clean (548
  members); three windDoc reveals from the final code verify on the reference verifier.
