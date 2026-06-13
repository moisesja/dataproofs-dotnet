# smoke (AC-10)

One minimal, self-contained console program per published package, each exercising the package's
core round-trip, printing a terminal `OK` line, and exiting `0` on success (any failed expectation
exits non-zero). These are the programs the AC-10 clean-room install job builds and runs.

| Folder | Package | What it does |
|---|---|---|
| `Core/` | `DataProofsDotnet.Core` | `eddsa-jcs-2022` Data Integrity proof: sign through a non-exporting NetCrypto key store, verify, and confirm a tampered document fails. |
| `Jose/` | `DataProofsDotnet.Jose` | Compact JWS (EdDSA): sign a payload, parse + verify with the public JWK, confirm a wrong key is rejected. |
| `Cose/` | `DataProofsDotnet.Cose` | `COSE_Sign1` (EdDSA): sign a payload, verify, confirm a tampered message fails. |
| `Rdfc/` | `DataProofsDotnet.Rdfc` | RDFC-1.0 canonicalization of a bundled JSON-LD credential through the **offline** loader (no network); asserts non-empty, deterministic N-Quads. |
| `DependencyInjection/` | `DataProofsDotnet.Extensions.DependencyInjection` | `AddDataProofs(...)` composition: resolve the pipeline + registry from the built provider and confirm the JCS suites registered. |

## The AC-10 clean-room procedure (run in `publish.yml`, and on `main` in `ci.yml`)

For each package the CI job does, in a clean temp directory:

```bash
dotnet pack <package> -o ./local-feed              # all five packed to a local folder feed
dotnet new console -n SmokeApp && cd SmokeApp
dotnet add package <package-id> --source ../local-feed   # plus the documented prerequisite only
# replace the generated Program.cs with this folder's Program.cs (and, for Rdfc, the bundled .jsonld)
dotnet run                                          # must print "OK — … smoke passed." and exit 0
```

Documented per-package prerequisites (the only extra `dotnet add package` allowed):

| Package | Prerequisite | Why |
|---|---|---|
| `Core` | `NetCrypto` | the `ISigner` / `IKeyStore` signing substrate |
| `Jose` | `NetCrypto` | the signer substrate (`JwsSigner` wraps an `ISigner`) |
| `Cose` | `NetCrypto` | the signer substrate |
| `Rdfc` | *(none)* | dotNetRDF rides transitively and is never surfaced |
| `Extensions.DependencyInjection` | `Microsoft.Extensions.DependencyInjection` | the container that hosts `AddDataProofs` |

## Checked-in form vs. local validation

The checked-in `*.csproj` files use **`PackageReference`** with pinned versions — the clean-room
form CI installs from the local pack feed (these do not restore from nuget.org until the packages
are published; that is by design, the install is what publishes them into the clean-room feed).

To validate a smoke program's *logic* locally against the repo source, build a throwaway project
that links the same `Program.cs` and swaps the package reference for a `ProjectReference` into
`src/` (NetCrypto / Microsoft.Extensions.DependencyInjection stay as package references). All five
were validated this way during development: each compiled and ran to its `OK` line and exit `0`.
