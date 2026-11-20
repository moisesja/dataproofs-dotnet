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
- [ ] `SdJwtVcConstants`: pin text, `AkaVctsClaim`, list, `[Obsolete]` on `TransitionalMediaType`, internal `Revision`.
- [ ] `SdJwtVcVerifier`: `dc+sd-jwt` only; `aka_vcts` format; -27 citations; doc notes.
- [ ] `SdJwtVcIssuer`: `aka_vcts` format; -27 citations.
- [ ] `ITypeMetadataResolver`, `SdJwtVcVerificationResult`, `SdJwtVerifier` doc notes.
- [ ] `PublicAPI.Unshipped.txt`.
- [ ] Tests: `vc+sd-jwt` rejected (and variants), fixtures from -27, `aka_vcts` disclosure rejected on both sides,
      `aka_vcts` format both sides; regression tests fail on `origin/main`.
- [ ] Sample, `samples/README.md`, PRD (FR-17, §9 AC-3 step 5, fixtures list, §12.2), concept table, CHANGELOG.
- [ ] Build `/warnaserror`, full test run, `ac-7`, `ac-9` (+ every sample), `ac-12`.
- [ ] Adversarial pass (30 min).
- [ ] PR, CI green.

## Review

(Filled in as review rounds happen.)
