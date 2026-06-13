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
