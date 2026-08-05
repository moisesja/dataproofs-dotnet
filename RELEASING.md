# Releasing

Releases are tag-driven and gated.

**The first release ships as a preview**, not `v1.0.0`. Tag it with a hyphenated prerelease
SemVer — e.g. `v0.1.0-preview.1` — which NuGet treats as a prerelease (consumers must opt in with
`--prerelease`). Cut a stable `v1.0.0` only once the line is ready (and the bbs-2023 conformant
binding has landed — see `docs/dependencies/netcrypto-bbs-header.md`).

1. Ensure `main` is green: all `ac-1` … `ac-11` jobs in `ci.yml` pass.
2. Update `CHANGELOG.md`: move `[Unreleased]` content under a new `## [x.y.z] - YYYY-MM-DD`
   (for the first release, `## [0.1.0-preview.1] - YYYY-MM-DD`).
3. Tag: `git tag v0.1.0-preview.1 && git push origin v0.1.0-preview.1` (or the next preview/stable).
4. The tag push queues `publish.yml`, which **stops immediately in the `nuget-release`
   environment awaiting approval**. The gate is on the whole job, so nothing runs before it —
   no checkout, no build, no OIDC login, no push. See [Approval gate](#approval-gate) below.
5. Approve it (or reject it) in the run page's *Review deployments* prompt. Only after approval
   does the job run: build → test → AC gates → **`ac-11` package-identity gate** (all five
   `DataProofsDotnet.*` IDs claimable-or-owned on nuget.org, ID prefix reserved, `PackageId`s
   exact) → pack → push to NuGet.org.

## Approval gate

The `nuget-release` environment carries a **required-reviewer** protection rule. Verified
configuration (2026-08-04, issue
[#20](https://github.com/moisesja/dataproofs-dotnet/issues/20)):

| Setting | Value | Why |
| --- | --- | --- |
| Required reviewer | `moisesja` (repo owner) | The only person who may release. |
| `can_admins_bypass` | `false` | Admins — including the owner — cannot push a deployment through without the review step. |
| `prevent_self_review` | `false` | Single-maintainer project: the person who pushes the tag must be able to approve it, or no release could ever ship. This is a known weakness of a one-person reviewer pool, not an oversight — it makes the gate a deliberate second action, not an independent second pair of eyes. |
| Deployment branch/tag policy | none | Any `v*` tag may reach the gate; the reviewer, not a ref filter, is the control. |

**Who approves, and when.** The repo owner approves, and only after confirming on the tagged
commit that: `main`'s `ac-1`…`ac-11` jobs are green, `CHANGELOG.md` has the matching version
section, and the tag's SemVer matches the [versioning policy](#versioning-policy) below. Reject
the deployment if any of those fail — a rejected deployment runs nothing and publishes nothing.

Re-verify the rule after any repository-settings change:

```
gh api repos/moisesja/dataproofs-dotnet/environments/nuget-release \
  --jq '{can_admins_bypass, rules: [.protection_rules[] | {type, prevent_self_review, reviewers: [.reviewers[]?.reviewer.login]}]}'
```

An empty `protection_rules` array means the gate is gone and every `v*` tag publishes
automatically — which is exactly the state that let v1.2.0 ship unreviewed (issue #20).

Publishing uses **NuGet Trusted Publishing (OIDC)** — no long-lived API key is stored. The
publish job requests a GitHub OIDC token (`id-token: write`), `NuGet/login@v1` exchanges it for a
short-lived (~1-hour) key against the nuget.org Trusted Publishing policy, and the push uses that
temporary key.

One-time owner actions (cannot be automated):

- Reserve the `DataProofsDotnet` ID prefix on nuget.org (AC-11 fails closed until done).
- ~~Create the `nuget-release` environment with required reviewers (no secret needed).~~ Done
  2026-08-04 — see [Approval gate](#approval-gate). The environment existed from 2026-06-13 but
  carried **no** protection rules until then.
- Create a **Trusted Publishing policy** on nuget.org (account → Trusted Publishing) for
  owner `moisesja`, repository `moisesja/dataproofs-dotnet`, workflow `publish.yml`, environment
  `nuget-release`.

The package version is derived from the tag (`v0.1.0-preview.1` → `0.1.0-preview.1`; `v1.0.0` →
`1.0.0`), overriding the dev-default `DataProofsVersion` in `Directory.Build.props` via
`-p:DataProofsVersion=`. The dev default is itself a `-preview` prerelease so local/CI packs are
never mistaken for a stable release.

## Versioning policy

SemVer applies to the **public .NET API surface** — the contract `ac-7` pins. On top of that, this
library emits standardized wire formats (JWS, JWE, COSE_Sign1, SD-JWT), so changes to *emitted
bytes* need their own rule:

- **Major** — a breaking change to the public .NET API, or a change to emitted output that was
  **already spec-conformant** (a conformant consumer could legitimately have depended on it).
- **Minor** — a correction that brings emitted output **into** conformance with the governing RFC,
  where the previous output was invalid, even though the bytes observably change. A conformant peer
  could not have relied on the old bytes: strict verifiers were rejecting them. The bump is minor
  rather than patch precisely to signal "the wire changed, read the CHANGELOG."
- **Patch** — bug fixes with no change to emitted output for inputs that previously succeeded
  (including hardening that turns an untyped fault into a documented exception).

The three rules above govern what this library **emits**. Changes to what it **accepts** — the
parsers' input contract — follow a parallel rule:

- **Accept-set narrowing** ships as **patch** when every newly-rejected input was invalid under the
  governing RFC, so no conformant peer could have produced it and strict implementations were
  already rejecting it. It ships as **minor or major** when it rejects input that was spec-valid,
  because a conformant peer could legitimately still be sending it.

The asymmetry with the emitted-output rules is deliberate. Emitting different bytes changes what
*every* consumer sees, so a conformance correction there earns a minor. Refusing bytes that were
never valid changes behavior only for peers that were already broken against the wider ecosystem —
so it does not, by itself, earn more than a patch. Any release that narrows the accept-set MUST
still name the concrete upgrade-window consequence in the CHANGELOG, including whether this
library's own earlier output is among what is now rejected.

Any minor release carrying a wire-format correction MUST describe the observable delta in the
CHANGELOG and state what a consumer has to do about it.

**Worked example — 1.2.0 (issue #17).** `JwsBuilder` stopped emitting the unprotected
`"header": {"kid": …}` object, because carrying the same `kid` there *and* in the protected header
violates RFC 7515 §7.2 disjointness and made every signed envelope unverifiable to nimbus-jose-jwt.
The public API did not change, and the removed member was part of an invalid envelope, so this
shipped as **minor**, not major — while the CHANGELOG spelled out that verifiers reading only the
unprotected `kid` must fall back to the protected header (tracked downstream in
`moisesja/didcomm-dotnet#70`).

**Worked example — 1.2.1 (issue #19).** `JwsParser` started rejecting JWS whose protected and
unprotected header parameter-name sets overlap, per RFC 7515 §5.2 step 4 — the verify-side half of
the 1.2.0 fix. This shipped as **patch** under the accept-set rule: the public API is unchanged,
nothing about emitted output changed, and the newly-rejected shape was invalid, so nimbus-jose-jwt
and every other strict verifier already refused it.

The trade-off is on the record, because it is the uncomfortable case for this rule: the rejected
shape is precisely what **this library itself emitted up to 1.1.1**, so a 1.2.1 verifier cannot
verify envelopes from a peer still on ≤ 1.1.1, and consumers tracking a floating `1.2.*` range pick
that up without a deliberate opt-in. It stays a patch because the fix is not optional — no future
version can accept that shape and remain conformant — and because the resolution is to upgrade
senders to ≥ 1.2.0 rather than to pin verifiers back. A future accept-set narrowing that lacks
*both* of those properties should be treated as minor instead.
