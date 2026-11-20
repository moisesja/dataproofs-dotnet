# Plan: prepare release 2.1.0 (2026-11-20)

## Owner's intent

- 2026-11-19: after issues #50, #49, #48, #47, #46 and #45, "let's prepare release 1.6.0". Corrected the same day
  to "Let's do 2.1.0", because 2.0.0 is already on NuGet.
- 2026-11-20, approving this plan: "Yes, prepare but do not release". So this PR prepares the release only. No
  tag, no GitHub release, no publish, and no approval of the `nuget-release` deployment come from this work.

## Decisions

1. **The version is 2.1.0, a minor.** The owner decided this on 2026-11-19, before the issues were done, and every
   issue PR was held to "no source break" for it.
   - **The audit.** An independent read-only audit of v2.0.0..1b43268 (the PR #57 head, holding all six issues)
     confirms nothing in the range forces a major.
     - Public API: additions only. 90 lines were added to the Jose `PublicAPI.Unshipped.txt`, and no line was
       removed in any package.
     - Emitted output: the same input gives the same bytes, compared on `SdJwtVcIssuer` with awkward input.
     - Accept-set: it narrows for input that was spec-valid, which is minor material.
   - *Alternative: 2.0.1, a patch.* It lost: the API adds members, and the accept-set narrows for spec-valid input
     (`RELEASING.md`).
   - *Alternative: 3.0.0, a major.* It lost because nothing is source-breaking. The `[Obsolete]` on
     `SdJwtVcConstants.TransitionalMediaType` leaves its `PublicAPI` line unchanged, and SemVer §7 makes
     deprecation a minor.
2. **No sub-agent.** The change is documentation, three XML-doc comments and one version number.
3. **The CHANGELOG date** is the day this PR merges. A release tagged on a later day gets a one-line date commit
   first.
4. **The audit's five CHANGELOG gaps are fixed here, not filed.** They are inaccuracies in the notes this release
   ships (lesson of 2026-10-30, "A finding I can fix is a task, not a note"). One reaches `src`: the issuer XML
   docs omit the NumericDate range they refuse. That fix is documentation only; behaviour is unchanged.
5. **RELEASING.md gains a 2.1.0 worked example.** The re-pin from -16 to -27 is the first accept-set narrowing
   whose newly refused input was valid under the previous pin and invalid under the new one. The policy did not
   say which draft "governs" in that case.
   - *Alternative: no worked example.* It lost because the next re-pin (to the RFC, PRD §12.2) would face the same
     question with no record. The owner can strike the rule sentence in review.

## Checklist

- [x] CHANGELOG: `## [Unreleased]` becomes `## [2.1.0] - <date>`, with a lead paragraph and a `### Why this is a
      minor and not a major` subsection.
- [x] CHANGELOG audit corrections:
  - [x] #45: the issuers refuse out-of-range NumericDates.
  - [x] #48: decoys inside a reserved claim are a spec-valid narrowing.
  - [x] #46 and #47: scope "nothing changes" to their feature.
  - [x] #50: NU1605 for a direct Cbor pin below 10.0.15.
  - [x] #49: `TransitionalMediaType` has no replacement constant.
- [x] XML docs on `SdJwtIssuer.IssueAsync` and `SdJwtVcIssuer.IssueAsync`: name the refused range.
- [x] `Directory.Build.props`: `DataProofsVersion` 2.0.0 becomes 2.1.0, and the comment follows.
- [x] RELEASING.md:
  - [x] the 2.1.0 worked example;
  - [x] fix the "-preview dev default" sentence;
  - [x] add the credentials-dotnet row to the downstream table.
- [x] Verify: build `/warnaserror`; the full test suite with zero skips; `dotnet pack` gives 2.1.0 packages;
      `git diff origin/main -- src/` shows only XML docs.
- [x] Independent check of the final CHANGELOG claims against the code.
- [ ] PR, with CI passing 12/12.
- [ ] Thorough review; fix findings; merge on a ready verdict for the current head. No tag.

## Review

### Before the PR: the independent claim check (7fea1d9 → a11a0e7)

A fresh agent got the diff and the instruction to falsify every added claim. It used reproductions against the
2.0.0 NuGet packages, the spec texts and the downstream repositories, and did not see this plan.

**Twelve findings, all fixed in a11a0e7:**
- Four claims about this library's own output or its API were wrong:
  - "every new property is `init`": 45 of the 49 are get-only;
  - "`SdJwtVcIssuer` never produced one": false for a caller-built `_sd`;
  - the repeated-digest entry's "own output unaffected": false for caller-built repeats;
  - the two RFC-valid shapes "have no conformant producer": the 2.0.0 issuers produced both.
- One spec reading was overstated: `vc+sd-jwt` under -16 was asked of Verifiers, and forbidden to Issuers.
- Two lists were incomplete:
  - the lead list missed the KB-JWT's own `nbf`/`exp` and a Disclosure named `_sd_alg`;
  - the worked example named two of "three" draft shapes, and its date range missed years before 0001.
- The credentials-dotnet row was wrong in two places: no project there references the DI package, and seven
  issues wait for this release, not four; #35 waits for none.
- The range wording was imprecise: "years 0001 to 9999" missed that 253402300799.5 is refused.
- The new dev-default sentence contradicted the `ci.yml` comment.
- The [Obsolete] tension was unstated: the policy says "no source has to change", and a warnings-as-errors
  consumer of the constant must change its source.
- RELEASING called the release "a patch" from the accept-set alone, but the additive API alone makes a minor.

I checked three findings myself before fixing them: the 4-of-49 `init` count from `PublicAPI.Unshipped.txt`, the
`ci.yml` comment, and the credentials-dotnet issues. That last check also showed its Cbor pin is at 10.0.15, so
the NU1605 note does not apply to it.

**Earlier evidence:**
- NU1605 was reproduced against a local 2.1.0 pack of Cose. The two local 2.1.0 packages it put in the global
  NuGet cache were removed afterwards.
- `dotnet build -c Release /warnaserror` is clean; `dotnet test` passes 4,042 tests with 0 skipped; `dotnet pack`
  gives all six packages at 2.1.0.

**Two new policy sentences for the owner to keep or strike** (RELEASING.md, worked example 2.1.0):
- "A narrowing whose refused shape has a known conformant use is a major."
- "marking a member `[Obsolete]` while keeping it working is a minor".
