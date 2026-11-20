# Plan — issue #45: SD-JWT and SD-JWT VC enforce `nbf` / `exp`

Branch `fix/issue-45-sd-jwt-vc-validity-window`, from `origin/main` at `f392d23`, with PR #56
(`feat/issue-46-x5c`, which carries PR #55, `feat/issue-47-type-metadata-processing`) merged in first, at `b0138bf`
and then at `54cb69b` (both fast-forwards), so the fix covers the verification entry points #55 and #56 add. Merges
land in order: #47 (PR #55), #46 (PR #56), then this. Release: 2.1.0, a minor, fixed by the owner and prepared
separately after the six issues of this run, so no version number is written here or in the CHANGELOG.

## Owner's intent

Issue #45, "Done when":

> - A past `exp` or a future `nbf`, beyond the clock skew, fails with a distinct, stable error code for each.
> - A present `nbf` or `exp` that is not a JSON number fails. Absent claims pass, because both are optional.
> - The check uses `CurrentTime` and `ClockSkew`.
> - The release notes call this out as a behaviour change.

From the parent for this run: cover every SD-JWT VC verification entry point (`VerifyAsync`,
`VerifyWithTypeMetadataAsync` from #55, `VerifyWithCertificateChainAsync` from #56); read the values from the
issuer-signed top-level payload, so a value a Disclosure introduces or a nested `credentialSubject.exp` is never what
decides; decide, from RFC 9901 §7.1, whether the generic `SdJwtVerifier` enforces the window too; settle NumericDate
semantics (fractions, exponents, out-of-range values, the boundary at now ± skew) consistently with the Key Binding JWT
`iat` check; new codes and options additive only; the CHANGELOG says plainly that credentials which verified before,
this library's own included, now fail when expired or not yet valid.

## Source check (read at the source, 2026-11-19)

`draft-ietf-oauth-sd-jwt-vc-27` (https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-27.txt), **§2.2.2.3
Registered JWT Claims** (the issue cites -16 §2.2.2.2; -27 renumbered it):

> The following registered JWT claims, including any of their subclaims, when used in the SD-JWT component of an
> SD-JWT VC, MUST NOT be included in Disclosures and therefore MUST NOT be selectively disclosed:
> [...]
> *  nbf: OPTIONAL.  The time before which the Verifiable Digital Credential MUST NOT be accepted.  See [RFC7519] for
>    more information.
> *  exp: OPTIONAL.  The expiry time of the Verifiable Digital Credential after which the Verifiable Digital
>    Credential is no longer valid.  See [RFC7519] for more information.

§2.4: "The recipient (Holder or Verifier) of an SD-JWT VC MUST process and verify an SD-JWT VC as described in Section
7 of [RFC9901]."

RFC 9901 (https://www.rfc-editor.org/rfc/rfc9901.txt), §7.1, which "The Holder or the Verifier MUST perform":

> 6.  Check that the SD-JWT is valid using claims such as nbf, exp, and aud in the processed payload, if present.  If a
>     required validity-controlling claim is missing (see Section 9.7), the SD-JWT MUST be rejected.

§9.7: issuers "MUST NOT allow any content to be selectively disclosable that is critical for evaluating the SD-JWT's
authenticity or validity" (`exp` and `nbf` listed), but "Verifiers cannot reliably depend on that and need to operate as
though security-critical claims might be selectively disclosable."

§7.3 step 5.h (the Key Binding JWT): "Check that the Key Binding JWT is a valid JWT in all other respects, per
[RFC7519] and [RFC8725]."

RFC 7519 (https://www.rfc-editor.org/rfc/rfc7519.txt):
- §2 NumericDate: "A JSON numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until the
  specified UTC date/time, ignoring leap seconds. [...] other than that non-integer values can be represented."
- §4.1.4 `exp`: "the expiration time on or after which the JWT MUST NOT be accepted for processing. The processing of
  the "exp" claim requires that the current date/time MUST be before the expiration date/time listed in the "exp"
  claim. Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock
  skew. Its value MUST be a number containing a NumericDate value."
- §4.1.5 `nbf`: "the current date/time MUST be after or equal to the not-before date/time listed in the "nbf" claim."
  Same leeway and number sentences.

## Decisions

1. **Release is 2.1.0 (minor), set by the owner. No public API is added or changed.** The check reuses
   `SdJwtVerificationOptions.CurrentTime` and `ClockSkew`; the codes are strings at the start of the error message, as
   every SD-JWT code is. No opt-out flag: a caller who must judge a credential at another instant sets `CurrentTime`.
   - Considered: a `ValidateLifetime` (default `true`) option, as some JWT libraries have. It would be additive, but
     the issue does not ask for it, `CurrentTime` already covers the one legitimate need (judging at a past instant),
     and a flag to accept expired credentials is a foot-gun on a verifier.
2. **The generic `SdJwtVerifier` enforces the window too, so every SD-JWT VC entry point inherits it.** RFC 9901 §7.1
   step 6 is part of the verification the Holder or Verifier "MUST perform", so the generic path must check `nbf` and
   `exp` "in the processed payload, if present"; this is where the RFC requires more than the literal issue.
   `SdJwtVerifier.VerifyCore` is the one function under `Verify`, `VerifyWithCertificateChain` and the three SD-JWT VC
   methods, so one check there covers all five. It runs after the payload is reconstructed (step 6 follows steps 3-5)
   and before the Key Binding JWT (§7.3 step 4 processes §7.1 first), so an expired credential never reaches the
   Type Metadata resolver or the KB-JWT check. The behaviour-change note covers both verifiers.
   - Considered: only the VC profile, keeping the generic verifier as it was. Lost: it leaves `SdJwtVerifier` short
     of a MUST, and the generic layer is what the VC verifier is built on.
3. **What is read: the top-level `nbf` and `exp` of the processed payload, which for an SD-JWT VC that can be accepted
   is the issuer-signed clear member.** A nested member (`credentialSubject.exp`) is never read: RFC 7519 claims are
   members of the claims set. For the generic SD-JWT, step 6 names the processed payload, so an `exp` the Issuer made
   selectively disclosable (which §9.7 says it must not, and which a verifier "cannot reliably depend on") is checked
   when disclosed; it is still Issuer-signed, through its digest. For an SD-JWT VC, the value checked is the signed
   one whenever the credential can be accepted, and cannot be steered: a Disclosure cannot add a top-level `exp` beside
   a clear one (reconstruction refuses the name clash, §7.1 step 3.c.ii.3), and one that adds it where none was clear
   is refused by the positional rule (`VC_DISALLOWED_DISCLOSURE`, -27 §2.2.2.3, issue #48), whichever value it carries.
   A withheld top-level Disclosure cannot be told from a decoy, so such a credential verifies without that claim, as
   FR-17 already says: keeping `exp` in the clear is the Issuer's duty.
   - Considered: read the signed payload in the generic verifier as well. Lost: a disclosed `exp` would then go
     unchecked in a generic SD-JWT, against step 6.
   - Considered: run a second, VC-only check on the signed payload after the positional rule. Lost: it accepts and
     refuses exactly the same presentations (the argument above), at the cost of a second code path. Only the error
     differs for a disclosed `exp`: `SD_JWT_EXPIRED` when it is past, `VC_DISALLOWED_DISCLOSURE` otherwise.
4. **Codes**, each a stable prefix of the message, distinct from the Key Binding JWT's `KB_JWT_*`:
   `SD_JWT_EXPIRED`, `SD_JWT_NOT_YET_VALID`, `SD_JWT_EXP_INVALID`, `SD_JWT_NBF_INVALID`. Both claims are judged, so a
   presentation can carry two of them. The SD-JWT VC verifier passes them through unchanged, as it passes every
   generic failure.
   - Considered: `EXPIRED` / `NOT_YET_VALID` as `JwtHandler` uses. Lost: in an SD-JWT result they would be ambiguous
     beside the KB-JWT's own `KB_JWT_EXPIRED` (the `iat` age bound).
   - Considered: `VC_EXPIRED` from the VC verifier. Lost: the check is generic, and no other generic failure is renamed.
5. **NumericDate (RFC 7519 §2).** A present member must be a JSON number (`GetValueKind() == Number`): a string,
   boolean, `null`, array or object is `*_INVALID`. The number is read as a `decimal` (exact for the decimal text a
   JWT carries, up to 28-29 significant digits; exponent notation such as `1.5e9` is accepted, as JSON allows) and must
   lie in [-62135596800, 253402300799], the whole seconds `DateTimeOffset` represents and the bounds `JwtClaims` and
   the KB-JWT `iat` already use. Outside that, including `1e400`, `-1e400` and integers beyond `decimal`, it is
   `*_INVALID`: refusing is fail-closed in all four directions (a far-future `exp` and a far-past `nbf` would have
   passed). Fractions are kept to the 100 ns tick; a remainder below one tick is rounded toward refusal (`exp` down,
   `nbf` up). `JwtClaims` and the KB-JWT truncate to whole seconds, which for an `nbf` accepts up to a second early;
   that is not repeated here. The number is first read at `decimal` precision (28-29 significant digits, rounded to
   nearest), so a fraction beyond that, about 1e-18 s at today's dates, is not exact (first adversarial pass, F3: the
   doc now says so; exact handling is not worth the code).
   - A `JsonValue` that wraps a .NET number (not parsed JSON) does not convert to `decimal`, so it is read as the JSON
     text it serializes to, the bytes that would be signed; a non-finite `double` has none and is refused. Unreachable
     through the public API, which reads parsed JSON on both sides, but the first adversarial pass (F4) showed a
     `long` refused, a trap for the next caller. Considered: `TryGetValue<long>` / `<double>` fallbacks. Lost: they miss
     `int`, `uint`, `float` and the rest, where the text covers every type the serializer writes.
6. **The boundary.** `nbf` fails when `nbf - now > ClockSkew`, the same comparison as the KB-JWT's
   `iat - now > ClockSkew`, so a value exactly at now + skew is accepted, as RFC 7519 §4.1.5 ("after or equal") says.
   `exp` fails when `now - exp >= ClockSkew`: RFC 7519 §4.1.4 says the current time "MUST be before" `exp`, so with no
   skew the instant `exp` itself is refused, and the leeway extends the window by exactly `ClockSkew`.
   - Considered: `now - exp > ClockSkew`, matching the inclusive style of the KB-JWT age bound and `JwtHandler`. Lost:
     with `ClockSkew = 0` it accepts at `now == exp`, which §4.1.4 forbids. The KB-JWT age bound is a verifier policy,
     not an `exp`, so it is not the same rule.
   - Both comparisons subtract two `DateTimeOffset`s (at most 3.2e18 ticks apart, inside `TimeSpan`) and compare
     `TimeSpan`s, so no `CurrentTime` and no `ClockSkew` can overflow them. A negative `ClockSkew` narrows the window
     on both sides (it can only refuse more); `TimeSpan.MaxValue` disables the time judgement but not the type check.
     Neither is refused: `SdJwtVerifier` documents only `ArgumentNullException`, and both are the caller's choice.
7. **`nbf` later than `exp`** is not refused as such. Each claim is judged on its own, as RFC 7519 defines it; with
   `ClockSkew = 0` such a credential fails at every instant, and with skew it can pass only inside the leeway the caller
   allowed.
8. **Issuance refuses a present `nbf` or `exp` that is not a NumericDate.** `SdJwtIssuer` already reconstructs what it
   is about to sign and refuses what its verifier refuses with every Disclosure presented (#54); a non-number `exp` is
   now among that, so it throws `MalformedJoseException` instead of signing a credential no verifier accepts (a .NET
   `DateTimeOffset` placed in the claims set serializes as a string, for instance). The time is not judged at issuance:
   an issuer may legitimately sign a credential that becomes valid later. `SdJwtVcIssuer` inherits it.
9. **The Key Binding JWT `iat` age bound no longer overflows.** `maxAge + ClockSkew` threw `OverflowException` out of
   the never-throws verifiers when both are large (`ClockSkew = TimeSpan.MaxValue`). It is now compared in 128-bit
   ticks. Same options, same entry points, so it is fixed here.
10. **The Key Binding JWT's own `nbf` and `exp` are judged too (this decision moved).** The first draft left them
    out as outside the issue. The first adversarial pass reproduced a KB-JWT whose `exp` had passed and whose `nbf`
    was ahead verifying on both verifiers (F2). RFC 9901 §7.3 step 5.h: "Check that the Key Binding JWT is a valid JWT
    in all other respects, per [RFC7519] and [RFC8725]", and `KeyBindingJwt.Verify` is code this PR already touches
    (decision 9), so by the repository's rule the defect is fixed here. Same function, same options, codes
    `KB_JWT_NOT_YET_VALID`, `KB_JWT_EXPIRED`, `KB_JWT_NBF_INVALID`, `KB_JWT_EXP_INVALID`. `KB_JWT_EXPIRED` is shared
    with the `iat` age bound on purpose: both mean the KB-JWT is too old to accept, with the same remedy (present
    again); the messages differ. This library's KB-JWTs carry neither claim.
    - Considered: a separate code such as `KB_JWT_EXP_PASSED`. Lost: two codes for one verdict, and an awkward name.
11. **Not done, deliberately:** a policy that requires `exp` to be present (RFC 9901 §9.7, "required
    validity-controlling claim"; `JwtValidationOptions.RequireExpirationTime` is the precedent); the Issuer JWT's `aud`
    and `iat`; refusing `nbf` later than `exp` at issuance; `JwtHandler`, whose `exp + skew` can overflow and whose `exp`
    boundary is inclusive; `SdJwtVerifier.Verify("")` throwing `ArgumentException` (adversarial F6, pre-existing).
    Reported to the parent as follow-ups with their cost.

## Items

- [x] `ValidityWindow` (internal): read and judge `nbf`/`exp`; shape-only check for the issuer.
- [x] `SdJwtVerifier.VerifyCore`: step 6 after reconstruction, before Key Binding.
- [x] `SdJwtIssuer.EnsureReconstructs`: refuse a non-NumericDate `nbf`/`exp`.
- [x] `KeyBindingJwt`: the age bound without overflow, and the KB-JWT's own window (decision 10).
- [x] XML docs: `SdJwtVerifier`, `SdJwtVcVerifier`, `SdJwtVerificationOptions`, `SdJwtIssuer`, `SdJwtVcIssuer`.
- [x] Tests (public API only, so they also run against `origin/main` and `54cb69b` to show the regression):
  window and boundaries both ways, type matrix, NumericDate edge values, skew and `CurrentTime` extremes, position
  (disclosed, nested, withheld), KB-JWT `exp` not confused with the Issuer's, duplicate members, every entry point,
  issuance refusal.
- [x] Pin `CurrentTime` in existing tests whose vendored or literal `exp` would lapse (1883000000 is 2029-09-02).
- [x] Samples: the window in `Samples.SdJwt` and `Samples.SdJwtVc`.
- [x] PRD FR-16, FR-17, AC-3; CHANGELOG under *Fixed*, headed as a behaviour change.
- [x] Build `/warnaserror`, full suite, gates (`ac-7`, `ac-9`, `ac-12` smoke).
- [ ] Adversarial pass; fix what reproduces.
- [ ] PR, CI green.

## Verification

Regression proof (the test files copied alone onto each base, built without `/warnaserror` because a doc `cref` names a
class the base lacks; `ValidityWindowTests` tests the new internal class and has no base to run on):
- `origin/main` (`f392d23`), `Issue45ValidityWindowTests` only (its APIs exist there): 84 of 91 fail. The 7 that pass
  are controls: inside the window, no claims, a nested `exp`, the three maximal-skew rows, and the two KB-JWT rows
  whose own claims are inside their window.
- `54cb69b` (#56 head, this branch's base), both files: 108 of 121 fail; the 13 that pass are those controls and the
  "inside the window" row of each of the six entry points.
- `dotnet build DataProofsDotnet.sln -c Release /warnaserror`: 0 warnings, 0 errors. `dotnet test DataProofsDotnet.sln
  -c Release`: 3,912 passed, 0 failed, 0 skipped (Jose 1,941, Rdfc 990, Core 539, Legacy 297, Cose 129, DI 11,
  ApiSurface 5). `tasks/dependency-hygiene` (ac-6), `tasks/api-surface-scan` (ac-7) and `tasks/samples-coverage` (ac-9,
  629 of 631 members covered, 2 allowlisted) clean; every sample exits 0; the ac-12 AOT smoke JIT and
  reflection-disabled legs emit and compare identical (29 values). No public API changed.
- Time bombs: the full Jose suite run with the default clock forced to 2035 fails only the test of that default, after
  pinning `CurrentTime` in the fixture-based tests (44 failed before).

## Adversarial pass 1 (fresh agent, issue + diff + specs + attack list, at `bf9b5af`)

No P1: no input made an expired or not-yet-valid credential verify, steered which `exp` is read, or got an exception out
of the five entry points (448 extreme combinations of `CurrentTime`, `ClockSkew`, `MaxKeyBindingAge` and KB `iat`).
Findings and what was done:
- F1 (P2) the CHANGELOG, PRD and `SdJwtVcVerifier` docs were not yet written: written (`ef5d607`, `9183c99`).
- F2 (P3) the KB-JWT's own `exp`/`nbf` never checked: fixed, decision 10 (`325805e`).
- F3 (P3) rounding below `decimal` precision is to nearest: documented, decision 5.
- F4 (P3) a .NET-backed `JsonValue` number refused: fixed, decision 5 (`325805e`).
- F5 (P3) issuer docs: non-finite doubles fail in the serializer (pre-existing), the range stated in seconds; `nbf` >
  `exp` at issuance left as decision 7.
- F6 (P3) `Verify("")` throws `ArgumentException`: pre-existing, outside the change, reported as a follow-up.
