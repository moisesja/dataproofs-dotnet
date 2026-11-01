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
  types booleans and numbers as XSD literals and drops the direction; JSON-LD 1.1 API §8.2.2 step 13.2
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

# Round 3 — patch dotNetRDF's RDFC-1.0 locally (approved 2026-10-30)

## Owner intent

Upstream's timing is unknown, so patch it here. This replaces "report upstream and document", which the
owner chose on a scope and cost I had wrong (see the lessons file). Also corrected: the round 2 note above
that "datasets without that shape are unaffected" was false.

## What the evidence showed

- A from-spec Python RDFC-1.0 and `rdf-canonize` 5.0.0 agree on 26,000 datasets; dotNetRDF 3.5.1 differs on
  56% of a 120-credential sample built around one shared nested value.
- Cause, proved by emulation (12,000 of 12,000 tree datasets) and by patching: `Remove(entry.Value[0])`
  uses the wrong key and the step 5 check tests the label, so labelled nodes are walked again. Either fix
  alone stops it; both match the specification. A self-reference was also counted twice.

## Decisions

- `Internal/Rdfc10Canonicalizer.cs`, a marked copy of the upstream file; `#nullable disable`; NetCrypto
  hashing for AC-6; `Assert` for the inaccessible `Triples.Add`.
- Added during implementation, not in the approved plan, because the fix required them:
  - The work budget (1,000 walks) only fit because of the defect: depth-64 chains failed ten existing tests.
    It is now 20,000 plus 4 per blank node.
  - The old budget also bounded recursion depth, so depth has its own limit plus a stack check.
  - `DirectLabelNQuadsFormatter`, because documents over 1,000 blank nodes now run the whole path, which
    made dotNetRDF's quadratic blank-node formatter a 69-second cost at 2.7 MB.
- From the adversarial review: permutations and large copies spend budget; a list whose permutations
  cannot fit is refused before any is tried, which also removes the `Permute` stack overflow; a repeated
  node is one permutation; predicates are hashed as written.
- Sort order stays UTF-16 code units, matching `rdf-canonize`, against the specification's code points.
- Not fixed: JSON-LD expansion cost, which is inside dotNetRDF. A cap is the owner's decision.

## Results

- Comparison with `rdf-canonize` on the real library: 0 of 26,000 differ; 0 unstable under reshuffling.
- Real signatures across implementations, 120 credentials: 1.5.0 verified 53 of the reference's proofs and
  the reference 53 of 1.5.0's; this branch 120 of 120 both ways. bbs-2023 on the tied shape: 4 of 4 both ways.
- Ablations: fixes 1 and 2 each alone change nothing, both together fail 4 tests; `Distinct` fails 2;
  predicate fails 3; removing the stack guard or the permutation check crashes the test host; the budget at
  1,000 fails 4; collapsing repeated nodes is pinned by `BlankNodeRepeatedAcrossManyGraphs_TakesOneWalk`.
  The copy and hash charges are performance-only, so no test pins them.
- Hostile inputs, this branch against 1.5.0: 500-byte N-Quads about 50 ms against over 30 s; the 2.9 MB JSON-LD
  crash is a 3.5 s refusal; the 4.2 MB padded input 2.1 s against 11 s.
- Adversarial review found no wrong accept.


# Round 4 — respond to the posted review comments (approved 2026-10-30)

## Owner intent

Look at the PR comments and address the valid ones thoroughly. Two reviews are posted, both against 90b7bc8,
with no inline threads, so each point was checked against head 68d2852. No runtime behaviour changes.

## What each comment needed

| Comment | Verdict | Outcome |
|---|---|---|
| Independent review: the direction loss is a dotNetRDF limitation, not the spec | Valid, mostly fixed in round 2 | Round 2 cited §8.2.2 step 12. The W3C text has the direction step at 13 and the i18n datatype at 13.2; corrected everywhere |
| Automated 1: departs from #40's opt-in | Already handled | The owner wrote #40 and approved D0; the CHANGELOG states the verifier cost |
| Automated 2: scoped-context interop edge | Valid, partly open | Pinned by tests; docs corrected (below) |
| Automated 3: the guard fires on a null or missing `@value` | Null was pinned; missing never reaches that guard | Both pinned: null in an array, a `@set` and a list; missing in three shapes |
| Automated 4: follow-ups for bbs `@list` and the constructors | Already handled | #43 is closed by this PR; the constructors are fixed in it |

## What the check showed

- dotNetRDF v3.5.1 `JsonLdParser.cs` and jsonld.js 9.0.0 `toRdf.js` both reach the direction branch only after
  the boolean and number branches, so "dependency limitation" is right. §5.3.2 was already cited correctly.
- The scoped-context difference is wider than the docs read. `VerifiableCredential` is a type-scoped term, so
  jsonld.js signs a plain `"x"` for `[credentials/v2, {"@direction":"rtl"}]`: every v2 credential that sets a
  default direction differs from ours, and a proof over one does not verify across the two.
- The docs said two differences; round 1 measured three. The duplicate quad was missing from the CHANGELOG,
  PRD and README, and is added.
- `{"@direction":"rtl"}` with no `@value` is not a value object. jsonld.js gives it a bare blank node and signs
  `rtl` and `ltr` alike. This library refuses it through `FindInNode`, which had no test.

## Results

- Gates on a clean Release build with `/warnaserror`: 3,033 tests pass, none skipped (10 added);
  `dependency-hygiene`, `api-surface-scan` and `samples-coverage` are clean; all 15 samples exit 0.
- Mutations, with the files restored and confirmed byte-identical: ignoring keywords on a node fails the three
  new no-`@value` rows and the existing node-object row; turning `rdfDirection` off fails all three scoped rows.
  The null rows and the scoped-reset test were not mutation-checked.
- No adversarial subagent: the only `src` change is a comment.
- Not addressed here: the two findings in `tasks/plan20261030-pr42-review.md`, which were never posted as PR
  comments, and the shelved size limits and number fixes.

# Round 5 — fix the two defects in review 5720216431 (approved 2026-10-30)

## Owner intent

The review of 6b66977 requested changes: `KnownContexts` could be bypassed with a nested context, and bbs-2023
issued base proofs its own derivation refused. Solve both in this PR. Both regressions were written first and
seen failing on 6b66977, which reproduced the review's findings here.

## Decisions

- **D1 — Implement, not defer.** About as small as removing the option, and the owner chose to have it here.
- **D2 — A nested `@context` follows the root's rule.** §4.6 step 3 fails any subtree's `@context`, but the JCS
  suites copy `@context` into each proof, so that reading refuses every JCS proof and W3C's own vectors, and a
  presentation embeds credentials with their own. §2.4.1 allows equivalent protections, and a listed context
  nested gives a holder nothing that adding it at the root does not.
- **D3 — Changed during the work.** The approved plan skipped `@value` as "never processed" and documented an
  explicit `{"@type":"@json","@value":…}` as a workaround for a literal typed by a term. The adversarial review
  disproved both. `@value` is a keyword only outside a container map: under an `@id` container it is a map key
  whose value the processor expands, so a live context passed the skip. And on a term already typed `@json`, the
  explicit spelling signs a different literal. Whether `@value` is the keyword depends on contexts Core cannot
  read, so no name-based skip is safe. The walker now has no exemptions: every key named `@context` counts, as
  step 3 reads, and a JSON literal holding one fails closed. This follows the plan's own tie-breaker: a wrong
  skip is a bypass, and a false refusal is only visible.
- **D4 — bbs-2023 refuses the key at issuance** with `ProofGenerationException`, and the parser is unchanged.
  The 32 bytes come from the reference (`bbs-2023-cryptosuite/lib/proofValue.js`); the pinned draft gives no length.

## Results

- Regressions written first: 18 Core and 8 RDFC tests failed on 6b66977; the map-key and JSON-literal tests then
  failed against the first version of the fix, which still had the skip.
- Gates on a clean Release build with `/warnaserror`: 3,068 tests pass, none skipped; `dependency-hygiene`,
  `api-surface-scan` and `samples-coverage` are clean; all 15 samples exit 0.
- Mutations on the final tree, with files and the whole diff restored identically: no descent into object members
  fails 19 Core and 5 RDFC tests; no descent into arrays, 6 and 1; no HMAC check, the 5 length rows; a `@value`
  skip put back, 1 Core and 2 RDFC.
- Adversarial review, rerun against the final walker: no relabeled document verifies with `KnownContexts` set, on
  the plain, `@id`-map, Legacy RDFC and bbs-2023 routes. It did not cover `ecdsa-rdfc-2019`, the Legacy
  `EcdsaSecp256r1Signature2019` suite, or a host without the BBS library.

## Reported to the owner, not fixed here

The same review found five more defects, reproduced by rerunning its tests. None came from this round's change.
The owner then asked for all five to be fixed in this PR, so they moved to round 6.

# Round 6 — fix the five remaining adversarial findings (approved 2026-10-30)

## Owner intent

"I want all to be fixed in this PR." Approved reading: "all" is the five defects listed at the end of round 5. The
shelved stash stays shelved, and three smaller notes from the same review stay out: `previousProof` at bbs-2023
issuance, a past `expires` accepted at issuance, and `/01` array indexes accepted though RFC 6901 forbids them.

## Decisions

- D1: a named `proofValue` limit of 1 MiB characters, enforced at parse and at serialization. NetCid's default of
  4,096 is what broke long proofs. A limit stays because BBS verification cost grows with proof length. Enforcing
  it on output means a proof this library returns can always be parsed back.
- D2: every statement a pointer selects must be a statement of the document. `Group` used to drop the rest
  silently, as the reference does. It is a rule about statements, not syntax: `…/@value` on a plain literal selects
  the same statement and keeps working.
- D3: a pointer may not end on a value object's member other than `@value`, which selects no statement, so D2
  cannot see it. Known residual: an issuer who aliases `@language` and points at the alias still selects nothing,
  which only weakens that issuer's own mandatory group.
- D4: a derived proof keeps the proof's `@context` only when the document has none. Documents with a `@context` are
  unchanged, keeping reference parity.
- D5: `KnownContexts` runs before the proofs, which reverses what the reviewer was told in round 5. It is the only
  automatic way to stop a holder choosing a URL the verifier fetches, because the suites load contexts during
  verification and Core cannot reach the loader. §2.4.1 requires validation after verification, and also allows "a
  different ordering of the steps, that provide the same protections". The cost: a refused document has empty
  `ProofResults`, so its per-proof diagnostics are gone. `Verified` is false either way.
- D6: an invalid `bbsPrivateKey` becomes `ProofGenerationException`, catching only `ArgumentException` so
  `BbsUnavailableException` still propagates. The message does not quote the key.

## Results

- Regressions: 24 of 54 failed on 68e6d69 for the right reasons, including the loader fetching
  `https://holder.example/contexts/v1`, which reproduced the one finding not yet rerun.
- Each fix removed, on the tree before the final comment and doc wording edits: default decode limit, 3 tests fail;
  no serialization limit, 1; no statement check, 5; no value-member check, 4; proof `@context` dropped, 1; key error
  not translated, 7; check moved back after the proofs, 3 (1 RDFC, 2 Core). Restores were byte-identical.
- Real interop with the reference, both directions. Ours verified there at 100 undisclosed statements (4,657
  characters), 1,000 undisclosed (43,059) and 120 mandatory pointers (base proof 7,756). The reference's verified
  here at 100 and 1,000 undisclosed (4,652 and 43,053).
- The PRD's claim about the reference was tested and corrected: on a language-tagged literal the reference signs
  and derives `…/@value` and then fails verification, but throws at signing for `@language` and `@type`.
- Adversarial review of the six fixes. D1 and D6 held. In 121 pointer cases it found no false refusal, and its
  findings against this round were fixed here, each with a test seen failing first:
  - D2's check passed when a pointer's `@value` landed on an identical plain value beside it, leaving the
    language-tagged claim unbound. A pointer may now end on `@value` only when the value object holds nothing else.
    One case both 68e6d69 and the reference verify is now refused: `…/0/@value` on an explicit `xsd:string` value with
    an identical plain value beside it. The whole value still works, so the simple rule stays.
  - A pointer to an `@id` only skolemization adds issued a base proof that could never be derived from, and leaked
    `ArgumentException` at derivation. Pointers are now checked against the document as given, which also restored
    the right message for a missing member of a value object, and made `SelectionNQuads`'s catch unreachable.
  - "An unlisted context is never loaded" was too strong: it holds for values a document names, and a listed context
    still brings its imports, scoped contexts and redirects. Docs corrected, and a test pins the listed case.
- Stored base proofs with a mandatory pointer D3 refuses cannot be derived from. Decided to keep it: 1.5.0 bbs proofs
  do not work with this code anyway (round 2, D4), and the reference refuses that pointer at signing.
- Documented, not changed: a pointer past a nested `@context` that reads as another statement of the document selects
  that one, and a pointer to `@context` selects no statement. Verification reaches about 10 seconds at the
  `proofValue` limit, genuine or not (24,000 scalars, 10.6 seconds, on a forged proof).
- The two new rules removed: no document check, 5 tests fail; `@value` allowed on any value object, 1. The earlier
  seven ran before these last changes, and interop was not rerun after them; both changes only add refusals.
- Everything else the review found went to the owner directly.
- Gates on a clean Release `/warnaserror` build (33 projects, 0 warnings): 3,100 tests pass, 0 skipped (Rdfc 802,
  Core 539, Jose 1,336, Legacy 278, Cose 129, DI 11, ApiSurface 5). Dependency hygiene, API surface scan and samples
  coverage clean. All 15 samples exit 0.
