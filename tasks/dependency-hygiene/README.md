# dependency-hygiene (AC-6)

Console tool enforcing the PRD §2.2 package dependency matrix for every project under `src/`.

```
dotnet run --project tasks/dependency-hygiene/DependencyHygiene.csproj -c Release -- [--src-root <dir>] [--skip-pack]
```

## What it checks

For each `src/*.csproj`:

1. **Project graph** — `dotnet list <project> package --include-transitive --format json`, then
   asserts the matrix over the full closure.
2. **Packed graph** — `dotnet pack` each project to a temp dir, reads the `.nuspec`
   `<dependencies>` groups, and asserts the matrix over the **direct** dependency set the consumer
   inherits. (`dotnet list` omits ProjectReferences; the tool reads them from the csprojs so the
   sanctioned mediators are detected — see below.)

## The matrix (PRD §2.2)

- **dotNetRDF / Newtonsoft.Json** — allowed only in `DataProofsDotnet.Rdfc`, or in a package that
  (transitively) references `DataProofsDotnet.Rdfc` (the sole sanctioned mediator). The DI package
  legitimately pulls them through its Rdfc project reference.
- **NetDid.\*, jose-jwt, SdJwt.Net / Owf.Sd.Jwt** — never permitted in any closure (no sanctioned
  path; NetCrypto does not pull them).
- **NSec.\*, NBitcoin.\*, Nethermind.\*** — crypto backends; allowed **only** transitively under
  `NetCrypto` (they are declared in NetCrypto's own nuspec). Forbidden as a direct reference or if
  present while `NetCrypto` is absent — "crypto arrives only through NetCrypto".

## Exit codes

- `0` — clean
- `1` — one or more matrix violations
- `2` — usage / environment error

## CI-only portion

The packed-graph step needs a working `dotnet pack`. In a restricted sandbox pass `--skip-pack` to
run only the project-graph check (a superset in coverage — it sees transitive deps too); the
packed-graph nuspec assertion then runs in CI (`publish.yml` / `ci.yml` on main) where pack is
available. Locally in this repo the full tool (both checks) reports CLEAN.

## Companion: banned-symbol scan (AC-6, the BCL-crypto half)

The other half of AC-6 — catching direct `System.Security.Cryptography` primitive use in method
bodies that a dependency check cannot see — is `Microsoft.CodeAnalysis.BannedApiAnalyzers` driven by
the repo-root `BannedSymbols.txt`, referenced from each of the five `src/` csprojs. It fails the
build (`/warnaserror`) on any banned hash/HMAC/signature/AEAD symbol; `CryptographicOperations.FixedTimeEquals`
is deliberately not banned (NFR-6). All five `src/` packages build clean against it.
