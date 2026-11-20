# Plan — issue #48: the must-not-disclose rule follows a claim's position

Branch `fix/issue-48-positional-reserved-claims`, from `origin/main` at `c4bf7fb`, with PR #52
(`fix/issue-49-sd-jwt-vc-27`) merged in, first at `58786eb` (a fast-forward) and then at `912b975` (merge `9657a51`),
so this work sits on the -27 re-pin it will land on. Release: 2.1.0, a minor, prepared separately after the six issues
of this run, so no version number is written here or in the CHANGELOG.

## Owner's intent

Issue #48, "Done when":

> - A nested claim named like a reserved claim can be issued, presented and verified.
> - A top-level reserved claim, or anything inside one, presented as a disclosure still fails with
>   `VC_DISALLOWED_DISCLOSURE`.
> - Tests cover both directions.

From the parent for this run: the rule applies to a Disclosure that resolves to a top-level member with a reserved
name, and to anything inside a reserved claim (a member of `status` or `cnf` under any name, an element of an array
claim such as `aka_vcts`, and so on down); a claim elsewhere that merely shares a reserved name is unaffected. The
issuance-side frame check follows the same rule; turn each row of the issue's table into a test; cover issuance and
verification. #45 (`nbf`/`exp`) and #47 (Type Metadata `sd`) come later: do not implement them, but keep the position
information where they can reach it if that is free. Align with PR #52.

Two later directions from the parent, after the PR #52 review (issue comment 7027343504) and #52's reply (7027726727):
- A rule checked only against the presented Disclosures can be bypassed by withholding them, so "anything inside a
  reserved claim" is enforced on the issuer-signed payload: any `_sd` or `{"...": …}` placeholder inside a top-level
  reserved claim is a violation, attached or withheld. Test withheld as well as attached.
- #52 now enforces `aka_vcts` by position with two helpers; generalize them to every reserved name, replacing the
  name-only check, and keep one mechanism, not two.

## Source check (read at the source, 2026-11-19)

`draft-ietf-oauth-sd-jwt-vc-27` (https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-27.txt):

- §2.2.2.3: "The following registered JWT claims, including any of their subclaims, when used in the SD-JWT
  component of an SD-JWT VC, MUST NOT be included in Disclosures and therefore MUST NOT be selectively disclosed:"
  iss, nbf, exp, cnf, vct, vct#integrity, aka_vcts, status. The list names JWT claims, which are members of the
  top-level claims set; "including any of their subclaims" extends it to everything inside them.
- Appendix C, -19, under "Address AD review": "Clarify that claims that must not be selectively disclosed includes
  their subclaims not being selectively disclosable". -16 §2.2.2.2 said only "MUST NOT be included in the
  Disclosures, i.e., cannot be selectively disclosed".
- §2.4: the recipient processes the SD-JWT as in RFC 9901 §7; nothing further on the registered claims.

RFC 9901:
- §4.1 rule 7: the payload "MUST NOT contain the claims _sd or ... except for the purpose of conveying digests"; "The
  same digest value MUST NOT appear more than once in the SD-JWT."
- §4.1.1: `_sd_alg` "MUST appear at the top level of the SD-JWT payload. It MUST NOT be used in any object nested
  within the payload."
- §4.2.4.1: an `_sd` array "MAY be empty in case the Issuer decided not to selectively disclose any of the claims at
  that level."
- §4.2.5: decoys "both to the _sd array for objects as well as in arrays".
- §7.1 step 3.b identifies embedded digests (objects with `_sd`, one-key `...` array elements); step 4: "If any digest
  value is encountered more than once in the Issuer-signed JWT payload (directly or recursively via other
  Disclosures), the SD-JWT MUST be rejected."

## Decisions

1. **Release is 2.1.0 (minor), set by the owner.** No public API change: everything new is internal.
2. **One mechanism: #52's `SdJwtVcClaimRules.SelectiveDisclosureViolation(signed, processed, name)`, run for every
   name on `MustNotBeSelectivelyDisclosed`** (this decision moved twice). It refuses (a) a reserved top-level claim
   absent from the issuer-signed payload but present in the processed one, which only a top-level Disclosure can
   produce, and (b) a reserved claim whose signed value holds a disclosure site anywhere inside it. The name-only loop
   and `EnforcedByPosition` are gone.
   - First design: the reconstructor recorded each Disclosure's claim path and the VC verifier refused a path that
     started at a reserved claim. It worked, and gave the path in the message, but needed position plumbing through
     the generic verifier (an internal property on `SdJwtVerificationResult`), and it could not see a withheld
     Disclosure.
   - Second design (after the PR #52 review): positions plus a scan of the signed reserved claims. Correct, but once
     #52 landed its helper, the two together were two mechanisms for one rule, which the parent ruled out. Rule (a)
     catches exactly what the positions caught that the scan does not (a reserved claim disclosed at the top level,
     and anything inside it), so the positions went. Removed with them: `DisclosurePosition`, the reconstructor
     overload, the result property and their tests.
   - The parent's first brief asked to keep position information for #45 and #47 "if that is free". With the
     positions unused here, keeping them would be dead code in the generic layer. #47's `sd` rules can use the same
     signed-versus-processed comparison at any claim path: a claim in the signed payload is in the clear; one only in
     the processed payload came from a Disclosure.
3. **A disclosure site is an `_sd` member whose value is anything but an empty array, or an array element that is an
   object whose only member is `...`** (the shapes RFC 9901 §7.1 step 3.b identifies). An empty `_sd` carries no
   digest, so nothing behind it is disclosable or withheld, and §4.2.4.1 allows it (second adversarial pass, A3).
   `_sd: null`, which the reconstructor ignores, fails closed. The scan is iterative so a deep caller-built claims set
   cannot exhaust the stack.
4. **Decoys inside a reserved claim are refused, and that may refuse a conformant credential.** RFC 9901 §4.2.5
   allows decoys in any `_sd` array, and -27 forbids Disclosures, not digests; but a decoy cannot be told from a
   withheld Disclosure, and the withheld case is a real bypass (the #52 review dropped an element of `aka_vcts` that
   the format check refused, under the same signature). Fail closed. `SdJwtVcIssuer` never produces the shape: it
   adds decoys only to objects a frame entry processes.
5. **Issuance: the frame check is the positional rule applied to the frame, plus the same disclosure-site scan on
   the claims set.** Every Disclosure a top-level entry makes (flat, structured, recursive, array element) sits at or
   under that entry's claim, so the top-level names decide; 2.0.0 already behaved this way. A caller can also build a
   disclosure site into a reserved claim of the claims set, which `SdJwtIssuer` signed as given (first adversarial
   pass, A9a). A `JsonValue` can wrap a .NET object that only becomes a JSON object when serialized (second pass, A2),
   and could serialize differently the next time (third pass, P3_06), so the issuer serializes the claims once, checks
   that JSON and hands that JSON to `SdJwtIssuer`. The same parse refuses duplicate member names (RFC 7519 §4), which
   had escaped as `ArgumentException`. A claims set the serializer cannot write (depth, a non-finite number, a throwing
   getter) still fails through the returned task, as it did inside `SdJwtIssuer`; depth behaviour is unchanged
   (checked from 60 to 200 against the generic issuer). Alternative: issue, then run the verifier's check on the
   result. Lost: it signs before it refuses.
6. **RFC 9901 §7.1 step 4, and `_sd_alg` at the top level only, in their own commits.** The reconstructor refused a
   repeated digest only within one `_sd` array or when a Disclosure resolved it twice (first pass, X1), and it skipped
   every `_sd_alg` member at any depth, so a digest under a nested one was never seen and the member vanished from
   the processed payload (second pass, A1). Now every embedded digest is tracked for the whole walk (`2317ec1`), and
   a nested `_sd_alg` is refused (this decision moved twice). `80880e8` refused it (§4.1.1 "MUST NOT be used in any
   object nested within the payload"); `2e18450` switched to keeping it as data, because `SdJwtIssuer` signs one from
   a caller's claims and the library refused its own output (third pass, P3_07); the PR #54 review showed that
   §4.1.1 is a MUST with no exception in §7.1 and that an issuer emitting the shape is an issuer bug, so `f7909a0`
   refuses it again, on both sides: the reconstructor in the clear, in a disclosed value and through a Disclosure's
   name, and the issuer before signing (decision 7). A Disclosure named `_sd_alg` beside the top-level one is a name
   clash (§7.1 step 3.c.ii.3, third pass P3_08). Own output refused by this: only SD-JWTs whose caller's claims held
   a member named `_sd_alg` below the top level (or framed the top-level one); in every release the issuer wrote
   `_sd_alg` at the top level only (checked per tag), so default issuance never produced it.
7. **`SdJwtIssuer` reconstructs what it is about to sign, as the verifier would with every Disclosure presented, and
   refuses to sign an SD-JWT that fails** (`f7909a0`). The review asked for issuance to reject a nested `_sd_alg`,
   including one a Disclosure introduces and one inside a .NET object in a `JsonValue`; parsing back the payload
   bytes and the encoded Disclosures and running the reconstructor sees exactly what a verifier will. Alternative: a
   dedicated walk for nested `_sd_alg` over the payload, the Disclosure values and the Disclosure names. Lost: three
   places to keep in step with the reconstructor, the issuer/verifier mismatch this PR has hit three times, and it
   leaves the other mismatches (duplicate member names, Disclosures named `_sd` or `...`, depth 63, caller-built
   `_sd` that does not reconstruct), which the self-check closes too. Cost: one parse and one reconstruction per
   issuance.
8. **Failure messages** are #52's: `SD-JWT VC claim 'x' MUST NOT be selectively disclosed (… §2.2.2.3)` for a top-level
   Disclosure (unchanged from 2.0.0) and `SD-JWT VC claim 'x' MUST NOT have selectively disclosable sub-claims or
   elements (…)` for a site inside one.

## Items

- [x] Positional rule for every reserved name through #52's helper; name-only check removed.
- [x] Signed-payload disclosure-site check, attached, withheld and decoy; empty `_sd` allowed.
- [x] `SdJwtVcIssuer`: frame check and claims-set scan through the same rules, on the claims as signed.
- [x] RFC 9901 §7.1 step 4 and §4.1.1 in the reconstructor, own commits, own tests.
- [x] Tests: the issue's table rows (and every other reserved name) nested under `credentialSubject` issue, present
      and verify; a reserved claim and every way of getting inside one is refused, attached and withheld, on issuance
      and verification; regression tests fail on `origin/main` and on #52's head.
- [x] PRD FR-16, FR-17 and AC-3 step 5, `SdJwtVcConstants`, issuer and verifier docs, sample, CHANGELOG.
- [x] Build `/warnaserror`, full test run, `ac-7`, `ac-9`.
- [x] Adversarial passes, fixes re-attacked.
- [x] PR #54, CI green (12 of 12 on `34ccbba`).

## Verification

- `Issue48ReservedClaimPositionTests` and `SdJwtDigestUniquenessTests` (121 tests, public API only) copied alone onto
  `c4bf7fb` (origin/main): 57 fail; onto `912b975` (#52's head): 44 fail; on this branch: 121 pass. The passing ones
  on the bases are guards: frame entries on reserved claims (already refused at the top level in every release),
  top-level reserved Disclosures, the `given_name` control row, clear-plus-Disclosure collisions, unreferenced
  Disclosures, distinct decoys, repeats 2.0.0 already refused, and (on #52's head) the `aka_vcts` cases #52 fixed.
- Mutation: with the signed-payload scan disabled, 12 tests fail (every withheld and decoy case). With the issuer
  signing the caller's claims instead of the JSON it checked, the P3_06 test fails. The empty-`_sd`, `JsonValue`,
  duplicate-member and nested `_sd_alg` cases each failed before their fix.
- Issuance depth: claims sets nested 60 to 200 deep give the same outcome through `SdJwtVcIssuer` as through the
  generic `SdJwtIssuer` (pass up to 63, the serializer's `InvalidOperationException` from 64), so the as-signed scan
  changes nothing there.
- `dotnet build DataProofsDotnet.sln -c Release --no-incremental /warnaserror`: 0 warnings, 0 errors.
- `dotnet test DataProofsDotnet.sln -c Release --no-build`: 3496 passed, 0 failed, 0 skipped (Jose 1525) at `34ccbba`;
  3509 (Jose 1538) after review round 1.
- `ac-7` `tasks/api-surface-scan`: clean. `ac-9` `tasks/samples-coverage`: OK, 549 members (547 covered, 2
  allowlisted); all 15 samples exit 0. No public API change, so `PublicAPI.Unshipped.txt` is untouched by this issue.

## Adversarial passes

**Pass 1** (fresh agent; given the issue, the diff of the first design, -27 and RFC 9901; 43 probes). Attacked:
array-element Disclosures, two or more levels inside `cnf` and `status`, parent Disclosures whose value reaches a
reserved member, a reserved claim in the clear and as a Disclosure, one digest at a reserved and an ordinary location,
unreferenced and decoy Disclosures, the generic versus the VC verifier, nested same-name claims, issuance through every
frame method, `HolderConfirmationKey` and caller-built `_sd`. No route got a reserved claim accepted, and no nested
same-name claim was refused. Findings, outside the first design: A9a (a caller-built `_sd` inside a reserved claim of
the claims set was signed; fixed, decision 5), A9e (a caller-built top-level `_sd`; not fixable by position, follow-up),
X1 (RFC 9901 §7.1 step 4 only partly enforced; fixed, decision 6), and withheld Disclosures inside reserved claims
(then accepted by design; reversed after the #52 review, decision 4).

**Pass 2** (fresh agent; given the rule, the diff of the second design, -27 and RFC 9901; 46 probes). Attacked the same
list plus placeholder look-alikes, scan-versus-reconstructor disagreement, the vendored fixtures, the never-throw
contract and cost on large inputs. No route around the rule. Findings: A1 (nested `_sd_alg` hid digests from step 4;
fixed), A2 (a `JsonValue`-wrapped object slipped past the issuer scan; fixed), A3 (an empty `_sd` inside a reserved
claim was refused; fixed). Not changed: a withheld top-level Disclosure of a whole reserved claim is indistinguishable
from a decoy (documented); a Disclosure named `_sd_alg` beside a clear one is not a name clash (generic, follow-up);
neither verifier checks `exp`/`nbf` (#45).

**Pass 3** (the pass 2 agent, sent back over the fixes at `80880e8`; 59 probes). A1 and A3 closed; A2's reported case
closed. Found: P3_06 (the issuer checked one serialization and signed another; fixed, decision 5), P3_07 (refusing a
nested `_sd_alg` refused the issuers' own output; decision 6 moved), P3_08 (a Disclosure named `_sd_alg` beside the
top-level one replaced it; fixed), a duplicate member name inside a reserved claim escaping as `ArgumentException`
(fixed), and the serializer's exceptions moving from the task to the call (restored). Attacked without success: the
signed-versus-processed rule against everything the positions caught, presented and withheld, per reserved name;
`_sd` values `null`, `{}`, `"x"`, `0`, `false`, `[null]`, `[1]`, `[""]`, `[[]]`, `[{}]` and escaped; an empty `_sd`
masking a site; every vendored fixture; size and depth.

## Follow-ups (not done here)

- Generic `SdJwtIssuer` input rule: refuse a caller-built `_sd`, `_sd_alg` or `...` placeholder in the claims set
  (RFC 9901 §4.1 rule 7). It signs them as given, and silently overwrites a caller's `_sd` when the frame makes digests
  at the same level. A top-level one can hide a reserved claim that no verifier can see.
- #45: neither verifier checks `exp` or `nbf` (RFC 9901 §7.1 step 6).

## Review

**Round 1, on `34ccbba`** (issue comment 7029609982): one P2. A nested `_sd_alg` is prohibited by RFC 9901 §4.1.1,
not ordinary data, so `2e18450` and the tests asserting validity were wrong; reject it during issuance and
reconstruction, including what Disclosures introduce; keep top-level and default-algorithm controls; correct the PRD,
CHANGELOG and PR description.
- Reproduced on `34ccbba`: the reviewer's payload, signed with `typ: dc+sd-jwt`, verifies on both verifiers and keeps
  `address._sd_alg`; so does the disclosed variant.
- Own output before changing anything: every tag's `SdJwtIssuer` writes `_sd_alg` only at the top level after
  applying the frame, and every tag's reconstructor skipped `_sd_alg` at any depth. So only caller-supplied nested
  `_sd_alg` (or a framed top-level one) was ever issued and verified; default issuance never produced it.
- Fixed in `f7909a0` (decisions 6 and 7). `SdJwtSdAlgPlacementTests` (24 tests with the digest file): 10 fail on
  `34ccbba`, all pass here; the passing ones there are the controls (top-level `sha-256`/`sha-512`, default
  algorithm, issuer controls), the clash test and the digest tests.
