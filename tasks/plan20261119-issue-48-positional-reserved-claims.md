# Plan — issue #48: the must-not-disclose rule follows a Disclosure's position

Branch `fix/issue-48-positional-reserved-claims`, from `origin/main` at `c4bf7fb`, with PR #52
(`fix/issue-49-sd-jwt-vc-27`, head `58786eb`, in review) merged in (a fast-forward) so this work sits on the -27
re-pin it will land on. Release: 2.1.0, a minor, prepared separately after the six issues of this run, so no version
number is written here or in the CHANGELOG.

## Owner's intent

Issue #48, "Done when":

> - A nested claim named like a reserved claim can be issued, presented and verified.
> - A top-level reserved claim, or anything inside one, presented as a disclosure still fails with
>   `VC_DISALLOWED_DISCLOSURE`.
> - Tests cover both directions.

From the parent for this run: the rule applies to a Disclosure that resolves to a top-level member with a reserved
name, and to anything inside a reserved claim (a member of `status` or `cnf` under any name, an element of an array
claim such as `aka_vcts`, and so on down); a claim elsewhere that merely shares a reserved name is unaffected. Apply
it where the reconstructor resolves digests by location; the issuance-side frame check follows the same rule; turn
each row of the issue's table into a test; cover issuance and verification. #45 (`nbf`/`exp`) and #47 (Type Metadata
`sd`) come later: do not implement them, but keep the position information where they can reach it if that is free.
Align with PR #52: -27 section numbers, `aka_vcts` reserved.

## Source check (read at the source, 2026-11-19)

`draft-ietf-oauth-sd-jwt-vc-27` (https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-27.txt):

- §2.2.2.3: "The following registered JWT claims, including any of their subclaims, when used in the SD-JWT
  component of an SD-JWT VC, MUST NOT be included in Disclosures and therefore MUST NOT be selectively disclosed:"
  iss, nbf, exp, cnf, vct, vct#integrity, aka_vcts, status. The list names JWT claims, which are members of the
  top-level claims set; "including any of their subclaims" extends it to everything inside them.
- Appendix C, -19, under "Address AD review": "Clarify that claims that must not be selectively disclosed includes
  their subclaims not being selectively disclosable".
- §2.4: the recipient processes the SD-JWT as in RFC 9901 §7; nothing further on the registered claims.
- §5.6.1 Claim Path: "a non-empty array of strings, null values, or non-negative integers … A string indicates that
  the respective key is to be selected, … a non-negative integer indicates that the respective index in an array is
  to be selected", applied from "the root element of the credential, i.e., the top-level JSON object" (§5.6.1.2).
  The position recorded here uses that form, so #47's `sd` rules can compare it with a Type Metadata `path`.

## Decisions

1. **Release is 2.1.0 (minor), set by the owner.** No public API change at all: the position type and the new
   reconstructor overload are internal.
2. **Where the position comes from: the reconstructor records the claim path of every Disclosure it resolves**, and
   `SdJwtVerificationResult` carries the list internally; `SdJwtVcVerifier` step 3 applies the rule to it.
   Alternatives and why they lost:
   - *Pass a VC predicate into the reconstructor and fail there*: puts an SD-JWT VC rule into the RFC 9901 layer, and
     needs a second internal `SdJwtVerifier.Verify` that threads it through and maps a special failure back to
     `VC_DISALLOWED_DISCLOSURE`. The reconstructor is still the only place positions are computed; the rule just reads
     them one layer up.
   - *Re-walk the issuer payload in the VC verifier*: a second digest resolver that could disagree with the first
     about placement (decoys, array placeholders, recursion), which is the class of bug this issue is.
   - *Record only the top-level claim name*: enough for #48, but #47 needs the full path to match Type Metadata
     `path` values; the full path costs one list push and pop per level.
3. **The rule, part 1: a presented Disclosure is refused when the first component of its path is a reserved
   name.** A top-level Disclosure's path is its own name; anything resolved inside a reserved claim, whether that
   claim is in the clear or itself a (refused) Disclosure, has the reserved name first. A Disclosure whose path
   starts anywhere else is allowed, whatever its own name. `SdJwtVcClaimRules.DisallowedDisclosure` holds both parts
   of the rule, and the issuer calls the same `SdJwtVcClaimRules.IsReserved` for the frame.
4. **Issuance: the frame check stays a check of the frame's top-level names, now stated as the positional rule.**
   Every Disclosure a frame entry produces (flat, structured, recursive, array element) sits at or under that entry's
   top-level claim, so the top-level names are exactly the first path components the verifier will see. 2.0.0
   already behaved this way, so issuance changes in message and documentation only; the tests pin both directions.
   Alternative: issue, then run the reconstructor over the result and apply the verifier's check. Lost: it signs
   before it refuses (a key-store signature for nothing), for a result the frame already determines.
5. **The rule, part 2 (this decision moved): a reserved claim whose signed value carries an `_sd` key or a `...`
   array placeholder anywhere inside it is refused, whether or not its Disclosure is attached.** The first draft of
   this plan did not refuse a digest with no Disclosure presented, because it cannot be told from a decoy and
   RFC 9901 §4.2.5 lets an Issuer add decoys anywhere. The PR #52 review (issue comment 7027343504) showed what that
   costs: withholding an array-element Disclosure inside the signed `aka_vcts` turned a value the format check
   refuses (`["urn:example:visible","urn:example:main"]` with `vct` `urn:example:main`) into one it accepts, under
   the same signature. The same holds for any reserved claim (`status.status_list` dropped from `status`). The
   parent directed the rule onto the signed payload, and the tie-breaker is the one the evidence supports: fail
   closed. The cost is one shape that may be conformant, decoys inside a reserved claim; `SdJwtVcIssuer` never
   produces it (it adds decoys only to objects a frame entry processes). Positions stay as part 1 because they give
   the precise path in the message when the Disclosure is attached, and they are the only check that sees a
   Disclosure referenced from the top-level `_sd`, whose name its digest hides.
   Alternative considered: refuse only digests and placeholders that a presented Disclosure does not match (the
   withheld ones). Lost: a decoy and a withheld Disclosure look the same, so it is the same check.
6. **Issuance applies part 2 to the claims set.** A caller can build an `_sd` key or a `...` placeholder into a
   reserved claim of the claims set, and `SdJwtIssuer` signs it as given (adversarial finding A9a); the verifier
   would refuse the credential, so `SdJwtVcIssuer` refuses it first with `MalformedJoseException`. Not covered: a
   caller-built top-level `_sd` (finding A9e), whose digests hide their names, so neither side can judge them; the
   generic issuer also overwrites a caller's `_sd` silently when the frame makes digests at the same level. That is
   a generic `SdJwtIssuer` input rule, outside this issue: listed as a follow-up.
7. **RFC 9901 §7.1 step 4 in the reconstructor, in its own commit.** "If any digest value is encountered more than
   once in the Issuer-signed JWT payload (directly or recursively via other Disclosures), the SD-JWT MUST be
   rejected." The reconstructor refused a repeat only within one `_sd` array or when a Disclosure resolved it twice
   (adversarial finding X1). It is in the code this PR changes, it is a few lines, and the brief's default is to fix
   such defects in the PR; the commit stands alone so it can be dropped without touching the rest. Every newly
   refused input is invalid under RFC 9901, and the library's own issuer never repeats a digest.
8. **Failure messages.** A top-level reserved Disclosure keeps the 2.0.0 text (`SD-JWT VC claim 'x' MUST NOT be
   selectively disclosed (… §2.2.2.3)`). One inside a reserved claim says so and gives the path, so the reason is
   visible: `a Disclosure at 'status.status_list.idx' is inside SD-JWT VC claim 'status', whose subclaims MUST NOT be
   selectively disclosed either`. Path components are claim names from the signed payload or from Disclosures that
   matched a signed digest, the same source the 2.0.0 message already quoted.

## Items

- [x] Reconstructor records each resolved Disclosure's claim path (`DisclosurePosition`, `ClaimPathComponent`).
- [x] `SdJwtVerifier` passes the positions on through `SdJwtVerificationResult` (internal).
- [x] `SdJwtVcClaimRules.IsReserved` / `DisallowedDisclosure` / `ReservedClaimWithDisclosureStructure`;
      `SdJwtVcVerifier` step 3 uses them.
- [x] `SdJwtVcIssuer` frame check uses `IsReserved`, and the claims set gets the structure check; message and docs
      say "and its subclaims".
- [x] Signed-payload structure check (decision 5, after the PR #52 review), with withheld and decoy tests.
- [x] RFC 9901 §7.1 step 4 (decision 7), own commit, own tests.
- [x] Tests: the issue's table rows (and every other reserved name) nested under `credentialSubject` issue, present
      and verify; a reserved claim and every way of getting inside one is refused, attached and withheld, on issuance
      and verification; reconstructor positions; regression tests fail on `origin/main` and on #52's head.
- [x] PRD FR-16, FR-17 and AC-3 step 5, `SdJwtVcConstants` docs, sample, CHANGELOG.
- [ ] Build `/warnaserror`, full test run, `ac-7`, `ac-9`.
- [ ] Adversarial pass (30 min).
- [ ] PR, CI green.

## Verification

(Filled in as it happens.)

## Adversarial pass

(Filled in as it happens.)

## Review

(Filled in as review rounds happen.)
