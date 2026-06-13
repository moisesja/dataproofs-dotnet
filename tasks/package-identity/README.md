# package-identity (AC-11)

Console tool — the **publish gate**. Confirms the five `DataProofsDotnet.*` package IDs are
claimable-or-owned, the `DataProofsDotnet` ID prefix is reserved, and each src csproj's `PackageId`
is exactly its intended ID, before first publish.

```
dotnet run --project tasks/package-identity/PackageIdentity.csproj -c Release -- --owner <nugetAccount> [--src-root <dir>] [--offline]
```

## What it checks

1. **Registration + ownership** (network). For each ID, queries
   `https://api.nuget.org/v3/registration5-semver1/{id-lowercase}/index.json`:
   - `404` → the ID is unregistered and **claimable**;
   - `200` → the ID exists and must be owned by `--owner`. Ownership is resolved from the nuget.org
     search service (`azuresearch-*.nuget.org/query?q=packageid:<id>` → `owners` array). A `200`
     owned by anyone else **fails** the gate.
2. **ID-prefix reservation** (network). Reports whether the `DataProofsDotnet` prefix is reserved to
   `--owner` (the search service marks packages under a reserved prefix with `verified: true`).
   Prefix reservation is a **one-time owner action** that cannot be automated — request it via the
   NuGet account (<https://learn.microsoft.com/nuget/nuget-org/id-prefix-reservation>). If it is not
   yet in place, the gate fails with a pointer to that action (AC-11 requires this).
3. **PackageId exactness** (local, always runs). Reads each `src/<Id>/<Id>.csproj`'s `<PackageId>`
   and asserts it equals the intended ID exactly (guards against a typo shipping under a squattable
   name).

`--offline` skips steps 1–2 and runs only the local PackageId assertion, documenting that the
registration/ownership/prefix checks run in `publish.yml` where the network is available.

## Exit codes

- `0` — all IDs claimable-or-owned, prefix reserved, PackageIds exact
- `1` — a gate issue (foreign-owned ID, PackageId mismatch, or prefix not yet reserved)
- `2` — usage / environment error

## Result against the current repo (`--owner moisesja`, online)

- **PackageIds:** all five exact — `DataProofsDotnet.Core`, `.Jose`, `.Cose`, `.Rdfc`,
  `.Extensions.DependencyInjection`.
- **Registration:** all five return **404 — claimable** (unregistered on nuget.org).
- **Prefix reservation:** `DataProofsDotnet` is **NOT reserved** to `moisesja`. This is the expected
  pre-first-publish state (a prefix cannot be reserved before any ID under it is published), so the
  tool exits **1** with the owner-action pointer — exactly the AC-11-specified behavior. Once the
  owner reserves the prefix and the IDs are claimed (or with `--offline` before then), the gate
  passes.
