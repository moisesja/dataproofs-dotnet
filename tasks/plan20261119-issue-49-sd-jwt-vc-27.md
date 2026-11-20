# Plan — issue #49: re-pin SD-JWT VC from draft-16 to draft-27

Branch `fix/issue-49-sd-jwt-vc-27`, from `origin/main` at `c4bf7fb` (PR #51 merged). Release: 2.1.0, a minor,
prepared separately after the six issues of this run, so no version number is written here or in the CHANGELOG.

## Owner's intent

Issue #49, "Done when":

> - Constants, docs and error messages name the new revision and its section numbers.
> - `aka_vcts` is on the must-not-disclose list.
> - `vc+sd-jwt` is no longer accepted by the SD-JWT VC verifier, or only behind an explicit opt-in, and the release
>   notes say so.
> - The process for the next move (RFC publication) is written down.

Settled by the parent for this run: minor release, so no source-breaking public API change (`TransitionalMediaType`
stays, marked `[Obsolete]`); the CHANGELOG states the `vc+sd-jwt` narrowing plainly, says whether this library's own
output is affected and what consumers do; rows owned by #48, #47, #46 and #45 are not implemented here; rows with no
code today get at most a doc note. The owner chose the PR review as the gate, so there is no separate plan check-in.

## Source check (read at the source, 2026-11-19)

- Datatracker API `doc/document/draft-ietf-oauth-sd-jwt-vc`: `rev` 27, `time` 2026-11-16T10:45:13Z, states `active`,
  `iesg-eva` (IESG Evaluation), `sub-pub`; `draft-ietf-oauth-sd-jwt-vc-28.txt` returns 404. -27 is the latest.
- Read in -27: §2.1, §2.2, §2.2.1, §2.2.2.1–§2.2.2.5, §2.4, §2.5, §3, §5, §5.3, §5.4, §5.7, §6, §7.1 and the
  Appendix C change log -17 … -27, each against the code. Read in -16 the same sections, to number the old citations.
- Normative text the decisions rest on:
  - -27 §2.2.1: "The Issuer MUST include the typ header parameter in the SD-JWT. The typ value MUST use dc+sd-jwt."
  - -27 Appendix C, -19: "Remove: 'Note that this draft used vc+sd-jwt as the value of the typ header … both
    vc+sd-jwt and dc+sd-jwt should be accepted as the value of the typ header for a reasonable transitional period.'"
  - -27 §2.2.2.3: "The following registered JWT claims, including any of their subclaims, when used in the SD-JWT
    component of an SD-JWT VC, MUST NOT be included in Disclosures and therefore MUST NOT be selectively disclosed:"
    iss, nbf, exp, cnf, vct, vct#integrity, **aka_vcts**, status.
  - -27 §2.2.2.2: aka_vcts "MUST be a non-empty array of case-sensitive strings … Each value MUST be a
    Collision-Resistant Name … The array MUST NOT contain the value of the vct claim of the SD-JWT VC."
  - RFC 9901 §9.11: profiles "specify an explicit type by including the typ header parameter … and … Verifiers check
    this value". The generic layer leaves `typ` to the profile.

Section map used for every citation (old code cited §3.5 / §3.2.2.2 / §3.2.2.1.1 / §6, which match neither -16 nor
-27):

| Topic | -16 | -27 |
|---|---|---|
| Media type | §2.1 | §2.1 |
| Issuer-JWT `typ` | §2.2.1 | §2.2.1 |
| `vct` | §2.2.2.1 | §2.2.2.1 |
| `aka_vcts` | — | §2.2.2.2 |
| Registered claims, must-not-disclose | §2.2.2.2 | §2.2.2.3 |
| Verification and processing | §2.4 | §2.4 |
| Retrieving documents via HTTP | — | §3 |
| Type Metadata / retrieval / local cache / processing | §4 / §4.3 / §4.3.4 / — | §5 / §5.3 / §5.3.4 / §5.7 |
| Integrity of referenced documents | §5 | §6 |
| SSRF | §6.1 | §7.1 |

## Decisions

1. **Release is 2.1.0 (minor), set by the owner.** No public member removed or changed incompatibly.
2. **`vc+sd-jwt`: removed from the SD-JWT VC verifier, no opt-in.** `SdJwtVcVerifier` accepts `typ` exactly
   `dc+sd-jwt`. Alternatives and why they lost:
   - *Opt-in flag on `SdJwtVerificationOptions`*: puts a VC-profile switch on the generic SD-JWT options type, and adds
     a public member that would itself need obsoleting at RFC publication.
   - *Opt-in parameter or overload on `VerifyAsync`*: same lifetime problem, plus a binary-breaking signature change or
     a second overload to keep in samples.
   - *Keep accepting it*: -27 §2.2.1 is a MUST for `dc+sd-jwt`, and -19 deleted the transitional sentence. W3C
     VC-JOSE-COSE now registers `application/vc+sd-jwt` for a different format (VCDM payload, no `vct`). Downstream
     needs the two forms told apart by `typ` (credentials-dotnet#35 "Done when": "neither is mistaken for the
     other"); an alias, even an opt-in one, keeps them conflated inside the verifier.
   Cost, measured: `SdJwtVcIssuer` has fixed `typ` to `SdJwtVcConstants.MediaType` (`dc+sd-jwt`) in every tag from
   `v0.1.0-preview.1` to `v2.0.0` (checked per tag with `git show <tag>:…SdJwtVcIssuer.cs`), so no SD-JWT VC this
   library issued is rejected. A token a caller built with the generic `SdJwtIssuer` and an explicit
   `typ: "vc+sd-jwt"` is. The generic `SdJwtVerifier` does not check `typ` (RFC 9901 leaves it to the profile), which
   stays as is and is now said in its XML docs.
3. **`TransitionalMediaType` stays, `[Obsolete]`** with a message naming the change; value unchanged. Its sample use
   becomes a demonstration that the verifier now rejects it.
4. **`typ` comparison stays exact and ordinal.** `application/dc+sd-jwt` and case variants were rejected before and
   still are. Widening the accept set to RFC 7515 §4.1.9 media-type equivalence is not asked for; no change.
5. **`aka_vcts`: new public constant `SdJwtVcConstants.AkaVctsClaim`, added to `MustNotBeSelectivelyDisclosed`** in
   -27 §2.2.2.3 order (between `vct#integrity` and `status`). The issuer's frame guard and the verifier's disclosure
   check both read that list, so both enforce it.
6. **`aka_vcts` format (-27 §2.2.2.2) is validated at issuance and verification.** When present it must be a
   non-empty array of non-empty strings that does not contain the `vct` value. This is the -18 row's claim; under -16
   `aka_vcts` was an unregistered claim with any value, so this narrows the accept set and the CHANGELOG says so.
   Alternative: only list it (the issue's "Effect" column). Lost because the constant would then name a registered
   claim whose rules the profile does not enforce, while it enforces `vct`'s; the fix is about twenty lines in the two
   files already changing, and the owner's standing rule is to fix such findings in the PR (lesson of 2026-10-30).
7. **One internal `SdJwtVcConstants.Revision` string** feeds every error message, so the RFC move edits one string
   plus section numbers. Public would need a sample and outlive its usefulness; internal is enough.
8. **Fixtures re-vendored from -27** by `git mv tests/fixtures/ietf/sd-jwt-vc-16 → sd-jwt-vc-27` and replacing values,
   so the diff shows exactly what -27 changed (all five issuer-signed JWTs re-signed, two KB-JWTs re-issued, the
   Figure 3 email, two `vct#integrity` values, Appendix A.2 display strings; Disclosures and payloads unchanged).
   Appendix B became A, so the three appendix files are renamed. Extraction by a subagent with 742 scripted checks
   (digests, `sd_hash`, signatures against the RFC 9901 A.5 key with a stdlib P-256 verifier and bit-flip controls);
   independently re-checked here: every non-descriptive string in the twelve files occurs in the -27 text, and the
   test suite verifies the five issuer signatures and both KB-JWTs with the library's own verifier.
9. **Where the RFC-publication process lives: PRD §12.2**, with pointers from the `SdJwtVcConstants` XML summary and
   the fixture `PROVENANCE.md`. §12.2 is where the pin and its earlier re-verify checkpoint are recorded, and the PRD
   is the normative document contributors are told to keep current. Alternatives: `RELEASING.md` (about cutting
   releases, not tracking specifications), `CONTRIBUTING.md` (generic), a new `docs/` page (one more place to keep in
   sync), an issue (not in the repository, and filing issues is out of this run's remit).
10. **`vct` and `aka_vcts` values must be well-formed UTF-16 at issuance** (added after the adversarial pass, finding
    1). Two caller strings that differ only in lone surrogates both serialize as U+FFFD, so the issuer could sign an
    `aka_vcts` holding the `vct` value and its own verifier then refused it. Alternatives: compare the serialized
    forms (re-serializes the claims set to check two claims, and still signs content the caller did not pass); fix
    lone surrogates for every claim in the generic `SdJwtIssuer` (right in the end, but outside this PR's files and
    a behaviour change for every SD-JWT; listed as a follow-up). A JSON-parsed lone-surrogate escape in either claim
    also now fails as `MalformedJoseException` instead of `InvalidOperationException`. Wire input cannot carry one
    (issues #28, #30), so verification is unchanged.

## The issue's table, row by row

| Rev | Change | This PR | Why |
|---|---|---|---|
| -17 | Processing Type Metadata, rejection for `mandatory`/`sd` | Doc note only | #47 owns it. `SdJwtVcVerificationResult.TypeMetadata` now says it is returned as retrieved, not processed per §5.7. |
| -18 | `aka_vcts`, must not be disclosed | **Yes** | Decisions 5 and 6. |
| -19 | `vc+sd-jwt` removed | **Yes** | Decisions 2 and 3. |
| -19 | Sub-claims of must-not-disclose claims | No | #48. |
| -19 | HTTP retrieval and SSRF rules | Doc note | On `ITypeMetadataResolver`, the only hook that may dereference a URL. |
| -20 | Issuer-identifier paths, `dir`, `svg_id` | No | #47; no issuer-metadata retrieval exists. |
| -21 | Only `claims`/`path`/`mandatory`/`sd` failures reject | No | #47. |
| -22 | Token Status List normative | Doc note | `StatusClaim` and the verifier summary say `status` is carried, not checked (§2.4 SHOULD check). |
| -24 | `x5c` rules; updates RFC 7800 | No | #46 owns `x5c`. Nothing here requires `sub`/`iss` with `cnf`, so the RFC 7800 update needs no change. |
| -27 | Types are `vct` and `aka_vcts` only | Doc note | On `SdJwtVcVerificationResult.Vct`; there is no type-matching helper. |
| — | Section numbers in messages and docs | **Yes** | Section map above; every SD-JWT VC citation in `src`, tests, samples, docs and the PRD. |
| — | RFC-publication process | **Yes** | Decision 9. |

## Change-log items the table does not list (read against the code)

- -20 "Type Metadata identity": -27 §5.3 "A Consumer retrieving Type Metadata MUST ensure that the vct value in the
  retrieved document is identical to the reference used to retrieve it." `SdJwtVcVerifier` returns whatever the
  resolver gives without that check. Not a one-line fix (it needs a decision on reject vs. drop), so: follow-up,
  proposed home #47.
- -17 "Moved the vct#integrity requirement to the general Type Metadata retrieval section" (§5.3, §6): `vct#integrity`
  is never verified. Proposed home #47.
- Pre-existing, noticed while here: the verifier rejects a Disclosure whose claim name is on the list **at any depth**
  (a nested `status` inside a custom object fails), while the issuer guards only the top level. -27 scopes the rule to
  the registered claims and their sub-claims, so the nested case is a false refusal. Proposed home #48, which defines
  the path scoping.
- -19 JWS JSON serialization "not explicitly defined": no effect, only the compact form is supported.

## Items

- [x] Worktree from fresh `origin/main`; merge #51's branch, then `origin/main` after #51 landed (fast-forward).
- [x] Confirm -27 is the latest; read the sections above.
- [x] Re-vendor fixtures to `sd-jwt-vc-27`.
- [x] `SdJwtVcConstants`: pin text, `AkaVctsClaim`, list, `[Obsolete]` on `TransitionalMediaType`, internal `Revision`.
- [x] `SdJwtVcVerifier`: `dc+sd-jwt` only; `aka_vcts` format; -27 citations; doc notes.
- [x] `SdJwtVcIssuer`: `aka_vcts` format; -27 citations.
- [x] `ITypeMetadataResolver`, `SdJwtVcVerificationResult`, `SdJwtVerifier` doc notes.
- [x] `PublicAPI.Unshipped.txt`.
- [x] Tests: `vc+sd-jwt` rejected (and variants), fixtures from -27, `aka_vcts` disclosure rejected on both sides,
      `aka_vcts` format both sides; regression tests fail on `origin/main`.
- [x] Sample, `samples/README.md`, PRD (FR-17, §9 AC-3 step 5, fixtures list, §12.2), concept table, CHANGELOG.
- [x] Build `/warnaserror`, full test run, `ac-7`, `ac-9` (+ every sample). `ac-12` left to CI: no serialization or
      reflection change.
- [x] Adversarial pass (30 min).
- [ ] PR, CI green.

## Verification

- `Issue49SdJwtVcRepinTests` copied alone onto `c4bf7fb` (origin/main): 38 of 57 fail, which is every regression
  test; the 19 that pass are guards (case and prefix variants 2.0.0 already refused, positive controls, round trips,
  the generic verifier).
- The four lone-surrogate tests fail when the strict UTF-8 check in `SdJwtVcClaimRules.ReadTypeValue` is removed.
  Their inputs are built inside the test from code units: xUnit serializes theory arguments and turned lone
  surrogates into U+FFFD, so the first version of that theory passed for the wrong reason.
- The -27 fixtures: all five issuer-signed JWTs and both KB-JWTs verify through `SdJwtVcVerifier`
  (`SdJwtVcProfileTests`, including two new Appendix A.1 tests).

## Adversarial pass

One fresh agent, given the issue, the diff, -27 and RFC 9901; 48 probes. Attacked: `vc+sd-jwt`
through the default verifier by casing, `application/` prefix, whitespace, JSON escapes, look-alikes, `cty`,
duplicate or non-string `typ`, `crit`, the KB-JWT header, JWS JSON serialization, default options and DI (none
registered); top-level `aka_vcts` disclosure via every `DisclosureFrame` method and hand-built Disclosures with
escaped names, collisions, recursion; the `aka_vcts` format rule on both sides; false refusals. Results:

1. Reproduced, fixed (decision 10): the issuer could sign `aka_vcts` containing `vct` via lone surrogates.
2. Reproduced, not fixed here: the verifier refuses a Disclosure on the must-not-disclose list at any depth, so a
   nested `related.aka_vcts` or `employment.status` that the issuer accepted is refused. Pre-existing for the other
   seven names; `aka_vcts` extends it. Path scoping is #48's, so it is listed as a follow-up for #48 and stated in
   the CHANGELOG.
3. Informational: `application/dc+sd-jwt` and case variants are refused (decision 4); now stated on `MediaType`.
4. Informational: whitespace-only or NUL `aka_vcts` values pass; Collision-Resistant Name is not checkable, as for
   `vct`.

No route got `vc+sd-jwt` accepted or a top-level `aka_vcts` disclosed.

## Follow-ups (not done here)

- #47: -27 §5.3 identity check of a retrieved Type Metadata document's `vct`; `vct#integrity` verification (§6).
- #48: scope the must-not-disclose match to the registered claims and their sub-claims for the seven names other than
  `aka_vcts` (adversarial finding 2; `aka_vcts` moved to the positional rule in review round 1), generalizing
  `SdJwtVcClaimRules.EnforcedByPosition` and `SelectiveDisclosureViolation`.
- New: the generic `SdJwtIssuer` (and `JwsBuilder` payloads) silently sign U+FFFD for a lone surrogate in any
  caller-built claim, and throw `InvalidOperationException` for a parsed lone-surrogate escape.
- New: the generic `SdJwtIssuer` (and so `SdJwtVcIssuer`) signs a caller-built claims set that already carries the
  reserved `_sd` member, which lets a caller hide a top-level claim in a digest the frame guard never sees (round-1
  adversarial note N1). RFC 9901 reserves `_sd`, `_sd_alg` and `...`; refusing them in input is generic SD-JWT work.

## Review

### Round 1 — review comment 7027343504 on `58786eb`

Two P2 findings, both reproduced first with tests that fail on `58786eb` (8 new cases, all failing there; the
positive control passes):

1. **Nested `related.aka_vcts` round trip regressed.** Issued by `SdJwtVcIssuer` with
   `DiscloseObjectProperties("related", "aka_vcts")`, it failed with `VC_DISALLOWED_DISCLOSURE`; it passes on the
   base. Cause: the verifier matched Disclosure names at any depth, and this PR put `aka_vcts` on that list. My
   CHANGELOG had described the regression instead of fixing it.
2. **Withholding an element Disclosure bypassed the `aka_vcts` format check.** The check read the processed payload,
   after reconstruction had dropped the withheld element, so a signed `aka_vcts` containing the `vct` value verified.

Decision (parent's direction): enforce the rule for `aka_vcts` by position, here, and leave the other seven names on
the name-only check for #48 to replace. Alternatives: implement #48's general rule here (duplicates #48, which is in
progress, and widens this PR); land #48 first (breaks the merge order #52 → #48). The helper is small so #48 can
generalize it: `SdJwtVcClaimRules.EnforcedByPosition` names the positional claims, and
`SelectiveDisclosureViolation(signed, processed, name)` refuses (a) a top-level claim absent from the signed payload
but present in the processed one, which can only come from a top-level `_sd` Disclosure, and (b) any `_sd` member or
`{"...": digest}` placeholder anywhere inside the signed value, presented, withheld or decoy. The placeholder test
mirrors `SdJwtReconstructor`'s. The name-only loop skips the positional names. The `aka_vcts` format check now reads
the issuer-signed value; once (b) holds it equals the processed value, so no test can tell the two apart, but the
check no longer depends on that reasoning.

Mutants, each caught: no site scan (7 failures), no nested skip (1), no top-level-from-Disclosure branch (1),
placeholders not detected (6).

A second adversarial agent reviewed the fix (64 probes, hand-built signed issuer JWTs with real digests, controls on
`58786eb` reproducing both findings). No defect. Its notes, acted on:
- F1: the `AkaVctsViolation` parameter doc still said "processed payload"; corrected.
- N1: a whole top-level `aka_vcts` Disclosure the holder withholds is indistinguishable from a decoy, so that
  credential verifies without `aka_vcts`. Inherent; `MustNotBeSelectivelyDisclosed` and the PRD now say so instead of
  "must be signed in the clear". Its root, the issuer accepting a raw `_sd` in caller claims, is a follow-up.
- N2: a decoy placeholder inside `aka_vcts` is refused; deliberate, since it cannot be told from a withheld element.
