# Plan — issue #47: process SD-JWT VC Type Metadata

Branch `feat/issue-47-type-metadata-processing`, from `origin/main` at `c4bf7fb`, with PR #54
(`fix/issue-48-positional-reserved-claims`, which carries PR #52) merged in at `34ccbba` (merge `2fa2d26`), so this
work sits on the -27 re-pin and the positional reserved-claim rule it will land on. Release: 2.1.0, a minor, set by
the owner and prepared separately after the six issues of this run, so no version number is written here or in the
CHANGELOG, and no public member is removed or changed incompatibly.

## Owner's intent

Issue #47, "Done when":

> With processing enabled:
> - integrity mismatches, `vct` mismatches, `extends` cycles (and an over-deep chain) and `mandatory` / `sd`
>   violations fail verification with stable codes;
> - issuance can be checked against a supplied metadata document;
> - the processed metadata (merged claims and display) is available on the result;
> - a resolver fault is distinguishable from a verdict.
>
> With processing off, behaviour is unchanged. The rules moved between -17 and -21, so implement against the
> revision chosen in the re-pin issue.

From the parent for this run: implement against -27 and cite it; integrity covers `vct#integrity`, `extends#integrity`
and any other integrity claim -27 defines, hashed through NetCrypto (`ac-6`); merge claim metadata by `path`, child
taking precedence, display arrays replaced, cycles and over-deep chains rejected; `mandatory` and `sd` with the rules
on what a child may change; display and rendering metadata as a typed result; keep the raw `TypeMetadata` member; the
library never fetches; every new serialized type in the Jose context (`ac-12`), every new public member in
`PublicAPI.Unshipped.txt` and a sample (`ac-9`), new FR text in the PRD. Build on #54's signed-versus-processed
comparison rather than a parallel mechanism. Stop if a part needs a new dependency or a source break.

## Source check (read at the source, 2026-11-19)

`draft-ietf-oauth-sd-jwt-vc-27` (https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-27.txt, the copy #49
fetched and vendored the fixtures from):

- §2.4: "a Holder or Verifier MAY process Type Metadata as described in Section 5.7. If Type Metadata is processed,
  the rules defined in Section 5.7 apply and can require the SD-JWT VC to be rejected."
- §5.2: the document "MUST be a JSON object"; `vct` REQUIRED; `extends`, `display`, `claims` OPTIONAL;
  "Consumers MUST ignore properties that are not understood."
- §5.3: "A Consumer retrieving Type Metadata MUST ensure that the vct value in the retrieved document is identical to
  the reference used to retrieve it. For the initial document, that reference is the SD-JWT VC's vct claim value. For
  a parent document, that reference is the immediate child's extends property value." "If the claim vct#integrity is
  present in the SD-JWT VC, its value MUST be an "integrity metadata" string as defined in Section 6."
- §5.4: "Consumers MUST retrieve and process Type Metadata for the extended type before processing the Type Metadata
  for the extending type." §7.4: "Consumers MUST detect such circular dependencies and reject the credential."
- §5.5.2: the parent's display "remains valid for the inheriting type unless that type defines its own display
  property, in which case the original display metadata is ignored."
- §5.6: "the claims property MUST be an array of objects, and each of these objects MUST conform to the definitions of
  the path, mandatory, and sd properties … otherwise, claim metadata processing fails. Other properties, including
  display and svg_id, do not cause claim metadata processing to fail." (the -21 narrowing). Validation fails when a
  path errors (§5.6.1), when "the Holder or Verifier can determine that a claim addressed by a claim metadata object
  with mandatory set to true was not included in the issued credential", or when "a claim selected by a claim metadata
  object's path is not selectively disclosable as required by its sd value". "A Verifier MUST NOT treat absence of a
  selectively disclosable claim from a presentation as evidence that the Issuer failed to include a mandatory claim."
  "A claim is selectively disclosable at a path if it is directly represented as a Disclosure for an object property
  or array element in the SD-JWT; it is not selectively disclosable solely because one of its ancestors is." Integer
  and null components "are evaluated against the array as issued, counting array elements that are not disclosed";
  "If a path selects an array element that is not disclosed, that element was included in the issued credential and
  is selectively disclosable; its contents are unknown, so any deeper path components select no claims."
- §5.6.1 / §5.6.1.2: `path` is "a non-empty array of strings, null values, or non-negative integers"; a string on a
  non-object, or null or an integer on a non-array, aborts "and return[s] an error"; a missing key or index removes
  the element from the selection.
- §5.6.3: `mandatory` is a boolean. §5.6.4: `sd` is `always` / `allowed` / `never`, default `allowed`.
- §5.6.5: same `path` in child and parent: "the child type's properties are combined with those of the extended
  type, with the child type's properties taking precedence"; "The contents of properties are never merged".
  §5.6.5.1: a child may turn `allowed` (or omitted) into `always` or `never` but "MUST NOT change a claim that is
  marked as always or never in the extended type to a different value"; it may set `mandatory` to true but "MUST NOT
  change a claim that is mandatory in the extended type to false". Figure 22 keeps the parent's order and appends the
  child's new entries.
- §5.7: "If Type Metadata is processed, it MUST be fully processed, including any extended types … If claim metadata
  processing or validation fails, the SD-JWT VC MUST be rejected. If Type Metadata processing is required by policy
  or ecosystem rules and the Holder or Verifier cannot retrieve or process the applicable Type Metadata, the SD-JWT VC
  MUST be rejected."
- §6: integrity for `vct`, `extends` and the three rendering `uri` properties; "the Consumer verifies that the
  retrieved document matches it before processing that document"; syntax is W3C SRI §3 only; "computes the digest of
  the octets of the retrieved document"; with several hash expressions "the Consumer MUST use the hash expressions with
  the strongest hash algorithm it supports; verification succeeds if the computed digest matches the digest value of
  any of those hash expressions. If verification fails, or if the Consumer supports none of the hash algorithms used in
  the integrity metadata, the retrieved document MUST be rejected and MUST NOT be processed further."
- Appendix C, -17 and -21, confirm the moves the issue names.

W3C SRI (REC 2016-06-23, the revision -27 cites): `integrity-metadata = *WSP hash-with-options *( 1*WSP
hash-with-options ) *WSP`; `hash-expression = hash-algo "-" base64-value`; `hash-algo` and `base64-value` are the
CSP2 productions (`"sha256" / "sha384" / "sha512"`, ABNF quoted strings, so case-insensitive per RFC 5234 §2.3;
`1*( ALPHA / DIGIT / "+" / "/" )*2( "=" )`); options after `?` are ignored; the digest is standard base64.

Vector check: the Figure 17 document as printed (indent removed, LF line ends, trailing LF) hashes to Figure 16's
`vct#integrity` `sha256-5qAmRHgxiSHIPqS+mLzrVKVWliOBm955Oj86pMrc5g4=` (recomputed with Python, and pinned by a test).

## Decisions

1. **Release is 2.1.0 (minor), set by the owner.** Everything is additive; no member's signature changes.
2. **Processing is opt-in through two new entry points, not new parameters on the old ones.**
   `SdJwtVcVerifier.VerifyWithTypeMetadataAsync` and `SdJwtVcIssuer.IssueWithTypeMetadataAsync` take a
   `TypeMetadataProcessingOptions`. Alternatives: (a) a new optional parameter after `cancellationToken` — compiles for
   every caller but breaks the CancellationToken-last convention (CA1068); (b) a new parameter before it — breaks
   positional callers that pass the token; (c) a `VerifyAsync` overload — `VerifyAsync(p, keys, null, …)` becomes
   ambiguous (CS0121, a source break) and trips RS0026. The old `VerifyAsync` and `IssueAsync` keep their bodies, so
   with processing off nothing changes.
3. **Processing needs the octets, so it has its own resolver contract.** §6 hashes "the octets of the retrieved
   document", which a `JsonObject` cannot give back. New `ITypeMetadataDocumentResolver.ResolveDocumentAsync(reference)`
   returns `byte[]?`, called for the `vct` and for every `extends` value; `LocalCacheTypeMetadataDocumentResolver` is the
   offline default (FR-10 posture). Alternatives: a default interface method on `ITypeMetadataResolver` (two code paths,
   one of which cannot check integrity — the "integrity present but skipped" hole) or a new constructor on
   `LocalCacheTypeMetadataResolver` (a second one-argument constructor makes `ActivatorUtilities` ambiguous, lesson
   2026-10-29). The library parses the octets itself: UTF-8 and unpaired-surrogate check (`JoseJson.RequireTranscodableJson`),
   duplicate members refused, depth 64, size bound (`MaxDocumentSize`, default 1 MiB).
4. **"Processing enabled" is "required by policy" (§5.7).** A resolver that returns `null` for the `vct` or any parent
   fails with `VC_TYPE_METADATA_UNAVAILABLE`: a verdict. A resolver that throws is a fault: the result carries
   `VC_TYPE_METADATA_RESOLVER_FAULT`, `IsValid` false, and the exception on the new `TypeMetadataResolverFault`
   (only the exception type goes in the message, which may otherwise carry internal host names). Cancellation of the
   caller's own token propagates as `OperationCanceledException`. At issuance a verdict is a
   `MalformedJoseException` and a fault a plain `JoseException` whose inner exception is the resolver's, so
   `catch (MalformedJoseException)` sees verdicts only. Alternatives: letting the resolver's exception escape
   `VerifyAsync` (today's behaviour) leaves a fault indistinguishable from any other crash and breaks the FR-23
   result contract; a new exception type adds a public type for one `catch`.
5. **Integrity (`TypeMetadataIntegrity`, internal check plus public `Matches` / `Compute`).** Parse the whole value by
   the SRI grammar; any token that is not `alg-base64[?options]` makes the value malformed (fail closed: §5.3 makes a
   malformed `vct#integrity` a violation). Algorithms are compared case-insensitively (ABNF); sha256, sha384 and
   sha512 are supported through NetCrypto; other algorithms (md5, sha1, sha3-…) are ignored as SRI ignores them; a
   supported expression whose digest is the wrong length is malformed. The strongest supported algorithm present is
   the only one used, and any of its expressions may match; none supported → rejected. Checked for `vct#integrity` (read
   from the issuer-signed payload, which #48 keeps in the clear) on the leaf and `extends#integrity` on every parent,
   before the document is parsed. `uri#integrity` in rendering metadata names resources the library never retrieves,
   so it is surfaced on the typed result and `TypeMetadataIntegrity.Matches` is the check a wallet runs on the bytes
   it fetched; a malformed one does not reject (display does not, -21).
6. **`vct` identity is ordinal string equality**, no normalization (§5.3 "identical"): case, trailing slash and
   percent-encoding variants are different types. The same identity detects cycles (a visited `vct`), and
   `MaxExtendsDepth` (default 8 hops) bounds chains that never repeat a string.
7. **Positional validation reuses the reconstruction, the generalization of #54's signed-versus-processed comparison.**
   `SdJwtReconstructor.Reconstruct` gains an optional internal trace that records, for every object of the processed
   payload, which members came from a Disclosure and how many `_sd` digests stayed unresolved, and for every array the
   as-issued element list (clear, disclosed, undisclosed). With no trace the reconstruction is byte-for-byte what it was.
   #54's two helpers compare top-level presence and signed-value structure; claim metadata needs the same comparison at
   every depth and inside Disclosure values, which only the reconstruction walk sees. Alternative: a second walker over
   the signed payload and the Disclosures, which duplicates the digest resolution (a parallel mechanism).
8. **What counts as determined absence (§5.6, mandatory).** A key missing from an object whose `_sd` digests all
   resolved (or, at issuance, where every unresolved digest is a decoy) is absent; an index beyond the as-issued array
   is absent; an object with an unresolved digest, or an undisclosed array element, leaves it undetermined, and that is
   not a violation (§5.6 MUST NOT). One inference is added: a missing final claim whose metadata is both `mandatory` and
   `sd: never` is a violation either way (not included, or hidden in a Disclosure), so it is refused even when the
   object has unresolved digests.
9. **Parity of issuance.** `IssueWithTypeMetadataAsync` issues with `IssueAsync` and then runs the verifier's own check
   on the issued SD-JWT with every Disclosure, treating unresolved digests as the decoys they are. The resolver is
   called after signing, from the signed `vct` and `vct#integrity`; a failing credential is never returned. Alternative:
   a separate frame-and-claims validator, which would be a second implementation of the rules.
10. **Fail closed on the four properties §5.6 names; ignore the rest.** `claims` not an array of objects, a `path` that
    is not a non-empty array of strings / nulls / non-negative int32s, a non-boolean `mandatory`, an `sd` outside the
    three values, a child loosening `sd` or `mandatory`, and the same `path` twice in one document all fail with
    `VC_CLAIM_METADATA_INVALID` or `VC_CLAIM_METADATA_OVERRIDE_INVALID`. The duplicate is a judgment call (the draft is
    silent; merging "by path" presupposes one entry per path, and two entries could disagree). Display, rendering and
    `svg_id` that are malformed are dropped from the typed result (`svg_id` also when it breaks §5.6's syntax, sits on a
    path with a null, or repeats). Document-level shape (`vct`, `extends`, `extends#integrity`) is required to
    process the chain, so a wrong type there is `VC_TYPE_METADATA_INVALID`.
11. **Typed result, no serializer.** `ProcessedTypeMetadata` (leaf `vct`, `name`, `description`, effective display and
    claims, the documents leaf first) and its parts are read from `JsonNode`, not deserialized, so nothing new enters
    `JoseJsonContext`; the JSON parse is `JsonNode.Parse`, which is AOT-safe. `SdJwtVcVerificationResult.TypeMetadata`
    keeps returning the leaf document on the new path.
12. **Array decoys.** RFC 9901 §4.2.5 allows decoys in arrays. -27 counts undisclosed elements positionally, so a
    decoy placeholder counts as an undisclosed element; metadata with index paths or `sd: never` on elements is only
    sound for an issuer that adds no array decoys (this library's issuer adds none). Documented, not worked around.

Error codes (stable prefixes, as the existing `VC_*` ones): `VC_TYPE_METADATA_UNAVAILABLE`,
`VC_TYPE_METADATA_RESOLVER_FAULT`, `VC_TYPE_METADATA_INVALID`, `VC_TYPE_METADATA_INTEGRITY_INVALID`,
`VC_TYPE_METADATA_INTEGRITY_MISMATCH`, `VC_TYPE_METADATA_VCT_MISMATCH`, `VC_TYPE_METADATA_EXTENDS_CYCLE`,
`VC_TYPE_METADATA_EXTENDS_DEPTH`, `VC_CLAIM_METADATA_INVALID`, `VC_CLAIM_METADATA_OVERRIDE_INVALID`,
`VC_CLAIM_PATH_INVALID`, `VC_CLAIM_MANDATORY_MISSING`, `VC_CLAIM_SD_VIOLATION`.

## Items

- [x] Reconstruction trace (internal), no behaviour change without it
- [x] Integrity: parse, strongest algorithm, NetCrypto hashing; `Matches` / `Compute`
- [x] Document resolver interface, local cache, processing options
- [x] Processor: retrieval, integrity, `vct` identity, chain, cycle, depth, parse and typed model, merge
- [x] Claim metadata validation against the traced payload (path, mandatory, sd)
- [x] `VerifyWithTypeMetadataAsync`, result members, fault handling
- [x] `IssueWithTypeMetadataAsync`
- [x] Tests: Figure 16/17 vector, A.2 document, every code, both directions, processing off unchanged
- [x] PublicAPI, sample section, samples-coverage report, PRD FR-17a / AC-3, CHANGELOG
- [x] Build `/warnaserror`, full suite, ac-6, ac-7, ac-9, every sample; the SD-JWT VC sample with reflection-based
      serialization disabled (no serializer is touched, so the ac-12 legs are not affected)
- [x] Adversarial pass, fixes with tests (two passes; see Review)
- [ ] PR

## Changes to the decisions during implementation

- Decision 5 moved once. The first parser refused a value with any token outside `alg-base64`, so `sha3-256-…`
  beside a good sha256 failed; SRI §3.3.3 drops a token whose algorithm it does not recognise. Now only the
  algorithm part must be alphanumeric, an unknown algorithm's token is ignored whatever follows it, and a supported
  algorithm's value must be standard base64 of the right length, and (adversarial F4) canonical.
- Decision 9 gained a second view. At issuance the validator runs on the credential as a verifier sees it and on the
  complete payload with array decoys dropped (adversarial F3), so the issuer refuses whatever the verifier refuses
  and a decoy cannot stand in for a mandatory element. Pass 2 showed the complete view also judged `sd` and path
  errors at indices the decoys had shifted, refusing credentials the verifier accepts; it now reports only a missing
  mandatory claim, which is what §5.6 ties to "the complete Unsecured Payload".
- New: a fixed selection budget (1,000,000 path selections per validation; first 4,000,000, lowered when the Windows CI runner took 11 s for about 7.5 million selections). The two size bounds do not bound the work,
  which is claims times selected elements (pass 2: 22 s for a 27,000-leaf credential against 27,000 claims). A fixed
  internal bound, like the reconstruction's depth 64, rather than another option.

## Review

### Merge of #54's head `5881d62` (merge `20a71c1`)

#54 now refuses a nested `_sd_alg` in the reconstructor (in the clear, in a disclosed value, or as a Disclosure's
name) and makes `SdJwtIssuer` reconstruct the bytes it is about to sign, refusing to sign what would not verify. The
merge was clean: the new throws sit beside the trace calls and do not touch them. The two issuance checks are layered,
not duplicated in purpose: `SdJwtIssuer`'s runs before signing, untraced, and decides whether the SD-JWT verifies at
all; `IssueWithTypeMetadataAsync`'s runs after, traced, on the signed bytes, and decides whether it satisfies its Type
Metadata. The second reconstruction therefore cannot fail; it repeats the walk only for the positions (a comment says
so). Full suite after the merge: 3,617 passed, 0 skipped; `git diff 5881d62 HEAD` holds only this issue's files.

### Adversarial pass 1 (fresh agent; issue, diff and -27 text only), on `e4b6743`

Five findings, all reproduced in its test file and then by a regression test of mine that fails on `e4b6743`:
F1 quadratic duplicate-path check and merge (1 MiB document: 113 s), F2 integrity hashed over a buffer the resolver
could still change (34 of 200 runs parsed an unhashed document; 271 of 500 threw past the result contract), F3 an
array decoy standing in for a mandatory element at issuance, F4 non-canonical base64 matched, F5 "immutable" lists
mutable through a cast. Fixed in `d0554eb`. Held: strongest-algorithm rule, md5/sha1, base64url, grandparent integrity,
`vct` variants (NUL, look-alikes, percent-encoding, slash, BOM) for leaf and parent, cycles, depth N/N+1, three-level
override limits, path encodings, nested and array `sd`, mandatory withheld versus never set, every resolver fault
shape, no retrieval before the signature, 200-deep nesting, duplicate members, lone surrogates, processing off.

### Adversarial pass 2 (same agent, over the fixes), on `d0554eb`

F1, F2, F4, F5 hold (Adv15 0.2 s; 0 of 214,600 and 0 of 213,000 racing runs). Canonical path keys are injective
(`"0"`/`0`, `null`/`"null"`, escapes, normalization forms, separators). Without array decoys issuer and verifier agree
over six shapes in both directions; canonical base64 accepts every conformant spelling for all three lengths; no new
exception type escapes. Two findings: the complete view judged `sd` and paths at shifted indices (issuer refused what
the verifier accepts), and the residual fan-out cost. Both fixed in the next commit, with regression tests that fail
on `d0554eb`.

### Review round 1 (thorough review, issue comment 7030160237, on `ab389da`)

Both findings reproduced before any change: six new tests fail on `ab389da`.

- **[P1] quadratic complete pass.** `[.. trace.AsIssued(array).Where(...)]` copied the array for every indexed path;
  allocation for 1,000 → 4,000 indexed claims grew 18 MB → 269 MB (15×), and the reviewer measured 2.66 GB at
  10,000. Fix (`a274a2a`): the complete view indexes the processed array, which at issuance already leaves the decoys
  out; the complete pass runs only for mandatory claims; the budget now charges each element a component is applied
  to as well as each it selects, so every unit of work is charged (renamed "path steps", still 1,000,000). After: 0.31
  MB / 1.25 MB / 3.1 MB (optional) and 0.62 / 2.5 / 6.2 MB (mandatory) at 1,000 / 4,000 / 10,000, linear. Test:
  `Indexed_paths_cost_work_linear_in_the_claims_at_issuance`, both kinds, plus the reviewer's 10,000 × 10,000 issuance.
- **[P2] a shifted shape error discarded absence.** The complete pass returned success at a non-object or non-array,
  dropping an absence another branch proved, and skipping the branches after it. Fix: drop only that branch and keep
  evaluating. Test: both row orders × key step and index step, each issuing on `ab389da` and refused now, plus a
  control where the shape error is the only oddity and the credential is still issued.
- **Same patterns elsewhere.** Searched the Type Metadata code, verifier side included: the as-issued view reads the
  per-array list `ReconstructionTrace.AsIssued` builds once and caches, and every other per-claim cost is linear (the
  path key, formatted once at parse; the error text, now formatted only for a finding). Every other early return in
  the validator and the processor is itself a refusal, so it cannot discard evidence of another refusal.

### Review round 2 (thorough review 5987613088, on `fa34704`)

**[P2] Long path keys bypassed the work bound.** Reproduced first (three new tests fail on `fa34704`): one optional
claim `["a", null, K]` with a 900,000-character `K`, over 2,000 objects, verified as valid; the reviewer measured 14.2 s
over 80,000 objects at 160,003 charged steps. Fix (`fdc0255`): the bound is in units of work charged before the work,
and a key component costs 1 + ⌊length/32⌋ units per object it is applied to (the member lookup and the Disclosure
lookup both hash the key); a path stops once nothing is selected.

**Every size-dependent operation, and its bound** (the parent asked for the full list, not line 98 alone). Defaults:
`MaxDocumentSize` 1 MiB, `MaxExtendsDepth` 8 (9 documents), JSON depth 64, `EntryBudget` 10,000 per chain, `WorkBudget`
1,000,000 per validation.

| # | Operation | Cost driver | Bound |
|---|---|---|---|
| 1 | Copy of the resolver's octets | octets | `MaxDocumentSize`, checked before the copy; once per document |
| 2 | Integrity: two character passes, stack-buffer decode, canonical re-encode, one hash | value + octets | linear, no allocation per expression; once per hop |
| 3 | UTF-8 / surrogate-escape scan, `JsonDocument.Parse` (strict) | octets | `MaxDocumentSize`; once per document |
| 4 | `vct`, `extends`, `extends#integrity`, `name`, `description` reads; ordinal `vct` comparison | value length | once per document |
| 5 | `visited` set (hash of each reference) | reference length | once per hop |
| 6 | Path components read, `CanonicalKey` built (length-prefixed, unescaped) | path text | `EntryBudget` on the component count; linear in the text |
| 7 | Duplicate-path set and `extends` merge dictionary, keyed by `CanonicalKey` | key length | once per entry |
| 8 | Display, rendering, SVG template reads; `OneOf` (`ValueEquals` against 2–3 constants) | string lengths | `EntryBudget` on entry counts; each string read once |
| 9 | `svg_id` GroupBy and syntax check | `svg_id` length | once per effective entry |
| 10 | Read-only result lists | counts | `EntryBudget` |
| 11 | `ProcessedTypeMetadata.Documents`, `SdJwtVcVerificationResult.TypeMetadata` | octets | the result keeps octets only; each access parses them once, at the caller's choice |
| 12 | Traced reconstruction (a second walk at verification; a second after #54's self-check at issuance) | credential | linear, once |
| 13 | `AsIssued` per array | array length | built once per array, cached |
| 14 | Key lookups (`TryGetPropertyValue`, `IsDisclosedMember`) | key length × selections | `WorkBudget`: 1 + ⌊len/32⌋ each, charged first |
| 15 | Index, null and `sd` checks; selection lists | counts | `WorkBudget`: 1 per element applied to and per element selected, charged first |
| 16 | Error messages | value sizes | at most 120 characters of a value; a path described by at most 4 components of 32 characters |

**Adversarial pass 3** (fresh agent; only task: disproportionate CPU or memory under the default limits; given the
list above as it stood at `fdc0255`). No CPU finding (worst 1.27 s within the limits) and no crash; three memory
findings, all linear but with large constants, and two observations:
- F1: dense entries (one claim with about 524,000 two-octet index components per 1 MiB document, 9 documents)
  allocated 99× and the result kept 55× alive (`JsonNode` materialization of the path array, a `ClaimPathComponent` per
  component, `Format` building a second `JsonArray`, the result holding the document trees).
- F2: a path error echoed the escaped path, 12× the document (6,290,870 characters).
- F3: the wildcard product allocates up to about 28 MB before the work bound stops it (capped; low).
- Observations: `Documents` deep-cloned the trees on every access (264 MB for the F1 chain); an integrity value of
  10,400 expressions allocated 28× its size.

Fixed in `2c0e067`: documents are read through `JsonElement` and no tree is built; the 10,000-entry bound is charged
from parsed array lengths before anything is read; the result keeps octets and parses on access; the canonical key is
length-prefixed; messages echo bounded text; the integrity check allocates nothing per expression. F3 stays capped by
the work bound (about 28 MB worst). The tests: `A_document_of_dense_path_components_is_refused_before_it_is_built`,
`Display_and_template_arrays_count_against_the_entry_bound` (three arrays), `Error_messages_repeat_a_bounded_part_of_a_document_value`
(four codes), `An_integrity_value_with_many_expressions_is_checked_without_allocating_per_expression`,
`The_result_keeps_octets_and_hands_out_documents_the_caller_owns`,
`A_path_description_is_bounded_and_the_canonical_key_is_not_escaped`; and two tests rescaled to the entry bound
(the review-1 10,000-index case and the pass-1 large-claims case now assert the refusal past the bound and success
within it). Twelve fail on `fa34704`.

PASS4_PLACEHOLDER
