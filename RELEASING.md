# Releasing

Releases are tag-driven and gated.

1. Ensure `main` is green: all `ac-1` … `ac-11` jobs in `ci.yml` pass.
2. Update `CHANGELOG.md`: move `[Unreleased]` content under a new `## [x.y.z] - YYYY-MM-DD`.
3. Tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. `publish.yml` runs: build → test → AC gates → **`ac-11` package-identity gate** (all five
   `DataProofsDotnet.*` IDs claimable-or-owned on nuget.org, ID prefix reserved, `PackageId`s
   exact) → pack → push to NuGet.org.
5. The publish job runs in the `nuget-release` environment — add required reviewers in repo
   Settings → Environments so each tag waits for approval. Scope the `NUGET_API_KEY` secret to
   that environment.

One-time owner actions (cannot be automated):

- Reserve the `DataProofsDotnet` ID prefix on nuget.org (AC-11 fails closed until done).
- Create the `nuget-release` environment with required reviewers and the `NUGET_API_KEY` secret.

The package version is derived from the tag (`v1.0.0` → `1.0.0`), overriding the dev-default
`DataProofsVersion` in `Directory.Build.props` via `-p:DataProofsVersion=`.
