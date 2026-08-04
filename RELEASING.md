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
4. `publish.yml` runs: build → test → AC gates → **`ac-11` package-identity gate** (all five
   `DataProofsDotnet.*` IDs claimable-or-owned on nuget.org, ID prefix reserved, `PackageId`s
   exact) → pack → push to NuGet.org.
5. The publish job runs in the `nuget-release` environment — add required reviewers in repo
   Settings → Environments so each tag waits for approval.

Publishing uses **NuGet Trusted Publishing (OIDC)** — no long-lived API key is stored. The
publish job requests a GitHub OIDC token (`id-token: write`), `NuGet/login@v1` exchanges it for a
short-lived (~1-hour) key against the nuget.org Trusted Publishing policy, and the push uses that
temporary key.

One-time owner actions (cannot be automated):

- Reserve the `DataProofsDotnet` ID prefix on nuget.org (AC-11 fails closed until done).
- Create the `nuget-release` environment with required reviewers (no secret needed).
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

Any minor release carrying a wire-format correction MUST describe the observable delta in the
CHANGELOG and state what a consumer has to do about it.

**Worked example — 1.2.0 (issue #17).** `JwsBuilder` stopped emitting the unprotected
`"header": {"kid": …}` object, because carrying the same `kid` there *and* in the protected header
violates RFC 7515 §7.2 disjointness and made every signed envelope unverifiable to nimbus-jose-jwt.
The public API did not change, and the removed member was part of an invalid envelope, so this
shipped as **minor**, not major — while the CHANGELOG spelled out that verifiers reading only the
unprotected `kid` must fall back to the protected header (tracked downstream in
`moisesja/didcomm-dotnet#70`).
