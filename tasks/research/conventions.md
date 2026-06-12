# Repo conventions to mirror in dataproofs-dotnet (PRD §2.1)

Research note for the scaffold/coding agent. Sources audited 2026-06-11 (read-only):
`/Users/moises/Projects/net-did` (NetDid 1.3.1, published), `/Users/moises/Projects/didcomm-dotnet`
(DidComm 0.1.0, pre-release), `/Users/moises/Projects/crypto-dotnet` (NetCrypto 1.0.0-preview.1 —
the FR-21 tooling precedent and the PublicApiAnalyzers precedent). Everything below is verbatim
from those repos unless marked "synthesis note".

All three repos: .NET 10 (`net10.0`), nullable enabled, implicit usings enabled, central package
management (`ManagePackageVersionsCentrally`), `src/` + `tests/` + `samples/` + `tasks/` layout,
`AGENTS.md` as the real file with `CLAUDE.md` a **symlink to AGENTS.md** (verified: all three are
`CLAUDE.md -> AGENTS.md` symlinks and byte-identical). dataproofs-dotnet currently has AGENTS.md
and CLAUDE.md as two separate regular files — consider converting CLAUDE.md to a symlink to match.

---

## 1. Directory.Build.props

### 1.1 net-did — `/Users/moises/Projects/net-did/Directory.Build.props` (verbatim)

```xml
<Project>
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <NetDidVersion>1.3.1</NetDidVersion>
    <GenerateDocumentationFile>true</GenerateDocumentationFile>
    <NoWarn>$(NoWarn);1591</NoWarn>
    <Deterministic>true</Deterministic>
    <EmbedUntrackedSources>true</EmbedUntrackedSources>
    <IncludeSourceRevisionInInformationalVersion>true</IncludeSourceRevisionInInformationalVersion>
    <ContinuousIntegrationBuild Condition="'$(GITHUB_ACTIONS)' == 'true'">true</ContinuousIntegrationBuild>
  </PropertyGroup>

  <!-- Shared NuGet package metadata for all publishable projects -->
  <PropertyGroup>
    <Authors>Moises E Jaramillo</Authors>
    <PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>
    <PackageProjectUrl>https://github.com/moisesja/net-did</PackageProjectUrl>
    <RepositoryUrl>https://github.com/moisesja/net-did</RepositoryUrl>
    <RepositoryType>git</RepositoryType>
    <PackageTags>did;decentralized-identity;ssi;did-key;did-peer;did-webvh;w3c;verifiable-credentials</PackageTags>
    <PackageReadmeFile>README.md</PackageReadmeFile>
    <IncludeSymbols>true</IncludeSymbols>
    <SymbolPackageFormat>snupkg</SymbolPackageFormat>
  </PropertyGroup>
</Project>
```

### 1.2 didcomm-dotnet — `/Users/moises/Projects/didcomm-dotnet/Directory.Build.props` (verbatim)

```xml
<Project>
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <LangVersion>latest</LangVersion>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <DidCommVersion>0.1.0</DidCommVersion>
    <GenerateDocumentationFile>true</GenerateDocumentationFile>
    <NoWarn>$(NoWarn);1591</NoWarn>
    <Deterministic>true</Deterministic>
    <EmbedUntrackedSources>true</EmbedUntrackedSources>
    <IncludeSourceRevisionInInformationalVersion>true</IncludeSourceRevisionInInformationalVersion>
    <ContinuousIntegrationBuild Condition="'$(GITHUB_ACTIONS)' == 'true'">true</ContinuousIntegrationBuild>
  </PropertyGroup>

  <!-- Shared NuGet package metadata for all publishable projects -->
  <PropertyGroup>
    <Authors>Moises E Jaramillo</Authors>
    <Company>didcomm-dotnet contributors</Company>
    <Copyright>Copyright (c) 2026 Moises E Jaramillo and didcomm-dotnet contributors</Copyright>
    <PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>
    <PackageProjectUrl>https://github.com/moisesja/didcomm-dotnet</PackageProjectUrl>
    <RepositoryUrl>https://github.com/moisesja/didcomm-dotnet</RepositoryUrl>
    <RepositoryType>git</RepositoryType>
    <PackageTags>didcomm;didcomm-v2;did;decentralized-identity;ssi;jwe;jws;messaging;dif</PackageTags>
    <PackageReadmeFile>README.md</PackageReadmeFile>
    <IncludeSymbols>true</IncludeSymbols>
    <SymbolPackageFormat>snupkg</SymbolPackageFormat>
  </PropertyGroup>
</Project>
```

### 1.3 crypto-dotnet — `/Users/moises/Projects/crypto-dotnet/Directory.Build.props` (verbatim — versioning precedent)

```xml
<Project>
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <!-- Preview line: hyphenated SemVer suffix marks every build as a NuGet prerelease.
         Release CI overrides this from the git tag (e.g. v1.0.0-preview.1 -> 1.0.0-preview.1). -->
    <NetCryptoVersion Condition="'$(NetCryptoVersion)' == ''">1.0.0-preview.1</NetCryptoVersion>
    <Deterministic>true</Deterministic>
    <EmbedUntrackedSources>true</EmbedUntrackedSources>
    <IncludeSourceRevisionInInformationalVersion>true</IncludeSourceRevisionInInformationalVersion>
    <ContinuousIntegrationBuild Condition="'$(GITHUB_ACTIONS)' == 'true'">true</ContinuousIntegrationBuild>
  </PropertyGroup>

  <!-- Shared NuGet package metadata -->
  <PropertyGroup>
    <Authors>Moises E Jaramillo</Authors>
    <PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>
    <PackageProjectUrl>https://github.com/moisesja/crypto-dotnet</PackageProjectUrl>
    <RepositoryUrl>https://github.com/moisesja/crypto-dotnet</RepositoryUrl>
    <RepositoryType>git</RepositoryType>
    <PackageReadmeFile>README.md</PackageReadmeFile>
    <IncludeSymbols>true</IncludeSymbols>
    <SymbolPackageFormat>snupkg</SymbolPackageFormat>
  </PropertyGroup>
</Project>
```

### 1.4 Synthesis notes for dataproofs Directory.Build.props

- **Versioning pattern**: one repo-level version property (`NetDidVersion` / `DidCommVersion` /
  `NetCryptoVersion`), each library csproj sets `<Version>$(XxxVersion)</Version>`, and release CI
  overrides it with `-p:XxxVersion=${TAG#v}` (didcomm/crypto style) or `-p:Version=` (net-did
  style). For dataproofs use a `DataProofsVersion` property; the crypto-dotnet
  `Condition="'$(NetCryptoVersion)' == ''"` guard is the one that makes the `-p:` override safe —
  copy that form.
- **Warnings-as-errors**: didcomm sets `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`
  repo-wide in props AND passes `/warnaserror` in CI; net-did sets neither (relies on default);
  crypto-dotnet passes `-warnaserror` only in CI. didcomm is the strictest and matches dataproofs
  PRD quality bar — recommend the didcomm form (props + CI flag).
- **XML docs**: `GenerateDocumentationFile=true` + `NoWarn 1591` repo-wide (net-did/didcomm).
  crypto-dotnet instead escalates per-package: in NetCrypto.csproj
  `<WarningsAsErrors>$(WarningsAsErrors);CS1591</WarningsAsErrors>` (missing public XML doc = error).
- **`LangVersion latest`** only in didcomm; harmless to include.
- Package metadata pattern: `Authors` = `Moises E Jaramillo`, `Apache-2.0` expression, project/repo
  URL `https://github.com/moisesja/<repo-name>` (so `https://github.com/moisesja/dataproofs-dotnet`),
  `RepositoryType git`, `PackageReadmeFile README.md`, `IncludeSymbols true`,
  `SymbolPackageFormat snupkg`. didcomm additionally has `Company`/`Copyright` lines.

### 1.5 didcomm `Directory.Build.targets` — README packing (verbatim, recommended for multi-package repos)

`/Users/moises/Projects/didcomm-dotnet/Directory.Build.targets`:

```xml
<Project>
  <!--
    Pack the repository README into every publishable package so the PackageReadmeFile set in
    Directory.Build.props resolves; without a packed README, `dotnet pack` fails with NU5039.

    This lives in Directory.Build.targets (imported AFTER each project body) rather than
    Directory.Build.props so $(IsPackable) is already resolved: test and sample projects set
    IsPackable=false and are skipped, while the six src libraries (IsPackable unset → true)
    include the root README. $(MSBuildThisFileDirectory) is the repo root, where README.md lives.
  -->
  <ItemGroup Condition="'$(IsPackable)' != 'false' AND Exists('$(MSBuildThisFileDirectory)README.md')">
    <None Include="$(MSBuildThisFileDirectory)README.md" Pack="true" PackagePath="\" Visible="false" />
  </ItemGroup>
</Project>
```

net-did and crypto-dotnet instead repeat `<None Include="../../README.md" Pack="true" PackagePath="/" />`
in each library csproj. For dataproofs (5 packages) the didcomm targets-file approach is the better fit.

---

## 2. Directory.Packages.props

All three use the identical CPM preamble:

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    ...PackageVersion entries...
  </ItemGroup>
</Project>
```

No `CentralPackageTransitivePinningEnabled`, no version variables — plain `PackageVersion` items
with comment headers grouping by purpose. Projects then reference packages with version-less
`<PackageReference Include="..."/>`.

### 2.1 net-did — `/Users/moises/Projects/net-did/Directory.Packages.props` (verbatim, current stable set)

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <!-- Cryptography -->
    <PackageVersion Include="NSec.Cryptography" Version="26.4.0" />
    <PackageVersion Include="NBitcoin.Secp256k1" Version="4.0.0" />
    <PackageVersion Include="Nethermind.Crypto.Bls" Version="1.0.5" />
    <!-- Encoding -->
    <PackageVersion Include="NetCid" Version="1.5.0" />
    <!-- Caching -->
    <PackageVersion Include="Microsoft.Extensions.Caching.Memory" Version="10.0.8" />
    <!-- Logging -->
    <PackageVersion Include="Microsoft.Extensions.Logging.Abstractions" Version="10.0.8" />
    <!-- Dependency Injection -->
    <PackageVersion Include="Microsoft.Extensions.DependencyInjection" Version="10.0.8" />
    <PackageVersion Include="Microsoft.Extensions.DependencyInjection.Abstractions" Version="10.0.8" />
    <PackageVersion Include="Microsoft.Extensions.Http" Version="10.0.8" />
    <!-- Identity / JWK -->
    <PackageVersion Include="Microsoft.IdentityModel.Tokens" Version="8.19.1" />
    <!-- Source Link -->
    <PackageVersion Include="Microsoft.SourceLink.GitHub" Version="10.0.300" />
    <!-- Testing -->
    <PackageVersion Include="Microsoft.NET.Test.Sdk" Version="18.6.0" />
    <PackageVersion Include="xunit" Version="2.9.3" />
    <PackageVersion Include="xunit.runner.visualstudio" Version="3.1.5" />
    <PackageVersion Include="FluentAssertions" Version="7.0.0" />
    <PackageVersion Include="NSubstitute" Version="5.3.0" />
    <PackageVersion Include="coverlet.collector" Version="10.0.1" />
  </ItemGroup>
</Project>
```

### 2.2 didcomm-dotnet — `/Users/moises/Projects/didcomm-dotnet/Directory.Packages.props` (verbatim — note: still on older preview/testing versions)

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <!-- DID resolution + SSI crypto substrate. 1.3.0 ships raw ECDH (X25519/P-256/P-384/P-521),
         IEEE P1363 ECDSA, off-curve point validation, and a public Concat KDF, so didcomm-dotnet
         no longer carries its own primitive layer — see PRD §3.1. -->
    <PackageVersion Include="NetDid.Core" Version="1.3.0" />
    <PackageVersion Include="NetDid.Method.Key" Version="1.3.0" />
    <PackageVersion Include="NetDid.Method.Peer" Version="1.3.0" />
    <PackageVersion Include="NetDid.Method.WebVh" Version="1.3.0" />
    <PackageVersion Include="NetDid.Extensions.DependencyInjection" Version="1.3.0" />
    <!-- Cryptography: NSec is needed only for XChaCha20-Poly1305 (XC20P), which net-did does not
         ship. secp256k1 comes in transitively through NetDid.Core (no direct ref needed). -->
    <PackageVersion Include="NSec.Cryptography" Version="24.4.0" />
    <!-- ASP.NET Core (transports) -->
    <PackageVersion Include="Microsoft.AspNetCore.TestHost" Version="10.0.0-preview.1.25120.3" />
    <!-- Caching -->
    <PackageVersion Include="Microsoft.Extensions.Caching.Memory" Version="10.0.0-preview.1.25080.5" />
    <!-- Logging -->
    <PackageVersion Include="Microsoft.Extensions.Logging.Abstractions" Version="10.0.0-preview.1.25080.5" />
    <!-- Dependency Injection -->
    <PackageVersion Include="Microsoft.Extensions.DependencyInjection" Version="10.0.0-preview.1.25080.5" />
    <PackageVersion Include="Microsoft.Extensions.DependencyInjection.Abstractions" Version="10.0.0-preview.1.25080.5" />
    <PackageVersion Include="Microsoft.Extensions.Http" Version="10.0.0-preview.1.25080.5" />
    <!-- Resilience (retry + timeout + circuit-breaker) for the Phase 5 HTTPS + WebSocket
         transports. Polly v8 is the .NET-idiomatic policy library and the user-confirmed
         Phase 5 choice for FR-TRN-08 / FR-TRN-11. Used via Polly.ResiliencePipeline; no
         extra Microsoft.Extensions.Http.Polly / .Resilience wrapper needed. -->
    <PackageVersion Include="Polly" Version="8.5.0" />
    <!-- OpenTelemetry (observability — NFR-04). 1.10.0 carries GHSA-8785-wc3w-h8q6
         and GHSA-g94r-2vxg-569j; 1.15.3 is the current patched line. -->
    <PackageVersion Include="OpenTelemetry.Api" Version="1.15.3" />
    <!-- Source Link -->
    <PackageVersion Include="Microsoft.SourceLink.GitHub" Version="8.0.0" />
    <!-- Testing -->
    <PackageVersion Include="Microsoft.NET.Test.Sdk" Version="17.12.0" />
    <PackageVersion Include="xunit" Version="2.9.3" />
    <PackageVersion Include="xunit.runner.visualstudio" Version="2.8.2" />
    <PackageVersion Include="FluentAssertions" Version="7.0.0" />
    <PackageVersion Include="NSubstitute" Version="5.3.0" />
    <PackageVersion Include="coverlet.collector" Version="6.0.3" />
    <!-- Benchmarks (NFR-07) -->
    <PackageVersion Include="BenchmarkDotNet" Version="0.14.0" />
  </ItemGroup>
</Project>
```

### 2.3 crypto-dotnet — `/Users/moises/Projects/crypto-dotnet/Directory.Packages.props` (verbatim — newest set; has PublicApiAnalyzers and the "test-only, forbidden in src/" comment pattern)

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <!-- Cryptography backends -->
    <PackageVersion Include="NSec.Cryptography" Version="26.4.0" />
    <PackageVersion Include="NBitcoin.Secp256k1" Version="4.0.0" />
    <PackageVersion Include="Nethermind.Crypto.Bls" Version="1.0.5" />
    <!-- Encoding -->
    <PackageVersion Include="NetCid" Version="1.6.0" />
    <!-- JWK -->
    <PackageVersion Include="Microsoft.IdentityModel.Tokens" Version="8.19.1" />
    <!-- Dependency injection -->
    <PackageVersion Include="Microsoft.Extensions.DependencyInjection.Abstractions" Version="10.0.8" />
    <PackageVersion Include="Microsoft.Extensions.DependencyInjection" Version="10.0.8" />
    <!-- Build-time only -->
    <PackageVersion Include="Microsoft.SourceLink.GitHub" Version="10.0.300" />
    <PackageVersion Include="Microsoft.CodeAnalysis.PublicApiAnalyzers" Version="3.3.4" />
    <!-- Testing -->
    <PackageVersion Include="Microsoft.NET.Test.Sdk" Version="18.6.0" />
    <PackageVersion Include="xunit" Version="2.9.3" />
    <PackageVersion Include="xunit.runner.visualstudio" Version="3.1.5" />
    <PackageVersion Include="FluentAssertions" Version="7.0.0" />
    <PackageVersion Include="NSubstitute" Version="5.3.0" />
    <PackageVersion Include="coverlet.collector" Version="10.0.1" />
    <!-- Test-only Keccak reference for FR-11 differential testing; must NOT appear in src/ -->
    <PackageVersion Include="BouncyCastle.Cryptography" Version="2.4.0" />
  </ItemGroup>
</Project>
```

Synthesis note: for dataproofs, start from the crypto-dotnet/net-did stable versions (NetCid 1.6.0,
Microsoft.Extensions.\* 10.0.8, SDK-test 18.6.0, xunit.runner.visualstudio 3.1.5, coverlet 10.0.1,
SourceLink 10.0.300), not didcomm's stale preview pins. **FluentAssertions is deliberately held at
7.0.0** — net-did CHANGELOG 1.3.1 records: "v8 introduced a paid commercial license (Xceed) that is
unsuitable for this open-source library." Do not bump it. Interop oracles (`jose-jwt`, `Owf.Sd.Jwt`)
follow the BouncyCastle pattern: a `<!-- Test-only ... must NOT appear in src/ -->` comment in
Directory.Packages.props and a reference only from the test project.

---

## 3. global.json

net-did and didcomm-dotnet are byte-identical:

```json
{
  "sdk": {
    "version": "10.0.100",
    "rollForward": "latestFeature"
  }
}
```

**crypto-dotnet has NO global.json** (verified absent; its CI uses `dotnet-version: 10.0.x`).
dataproofs PRD §2.1 lists `global.json`, so use the net-did/didcomm file above.

## 3.1 nuget.config

All three pin a single source. crypto-dotnet's variant has the most useful comment (verbatim):

```xml
<?xml version="1.0" encoding="utf-8"?>
<!-- Single, explicit package source: keeps restores reproducible across dev machines
     and CI, and avoids NU1507 source-mapping warnings under central package management. -->
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
```

(didcomm adds `protocolVersion="3"` to the `add` element; net-did is same as crypto without the comment.)

## 3.2 .editorconfig

net-did and didcomm have one; crypto-dotnet does not. didcomm's (head, representative):
`root = true`; `[*]` indent_style space, indent_size 4, `end_of_line = lf`, utf-8,
trim_trailing_whitespace, insert_final_newline; `[*.{cs,csx}]`
`csharp_style_namespace_declarations = file_scoped:suggestion`, var-when-apparent,
expression-bodied members when single line, `csharp_prefer_braces = when_multiline:suggestion`;
`[*.{json,yml,yaml}]` indent_size 2; `[*.md]` trim_trailing_whitespace = false. Copy didcomm's
(`/Users/moises/Projects/didcomm-dotnet/.editorconfig`) wholesale. CONTRIBUTING documents
"file-scoped namespaces, 4-space indentation".

---

## 4. PublicApiAnalyzers (crypto-dotnet only — the precedent for the ApiSurface gate)

Only crypto-dotnet uses `Microsoft.CodeAnalysis.PublicApiAnalyzers` (3.3.4 in
Directory.Packages.props under a `<!-- Build-time only -->` group). Wiring is entirely inside the
library csproj `/Users/moises/Projects/crypto-dotnet/src/NetCrypto/NetCrypto.csproj`:

```xml
<PackageReference Include="Microsoft.CodeAnalysis.PublicApiAnalyzers" PrivateAssets="All" />
...
<ItemGroup>
  <AdditionalFiles Include="PublicAPI.Shipped.txt" />
  <AdditionalFiles Include="PublicAPI.Unshipped.txt" />
</ItemGroup>
```

The text files sit **next to the csproj** (`src/NetCrypto/PublicAPI.Shipped.txt`, 169 lines, first
line `#nullable enable` then one fully-qualified symbol per line, e.g. `NetCrypto.AesCbcHmacCipher`;
`PublicAPI.Unshipped.txt` is just `#nullable enable`). No repo-wide props wiring — replicate
per-package in each of the five dataproofs src projects.

Additionally crypto-dotnet has a reflection-based dependency-hygiene test (the precedent for
dataproofs' `DataProofsDotnet.ApiSurface.Tests` AC-6/AC-7 gates):
`/Users/moises/Projects/crypto-dotnet/tests/NetCrypto.Tests/NonFunctional/PublicApiHygieneTests.cs`
— class `NetCrypto.Tests.NonFunctional.PublicApiHygieneTests` with three facts:

1. `ExportedSurface_ContainsNoBackendOrNativeTypes()` — walks `Assembly.GetExportedTypes()` and for
   every base type, interface, ctor/method parameter, return type, property (incl. index params),
   field, and event-handler type calls a recursive `CheckType(Type, string location, List<string>)`
   that unwraps `HasElementType` (T[], T&, T*) and generic arguments, flagging any type whose
   assembly simple name starts with a forbidden prefix
   (`private static readonly string[] ForbiddenAssemblyPrefixes = ["NSec", "NBitcoin", "Nethermind"];`)
   or whose namespace is/under `NetCrypto.Native`. Blocklist (not allowlist), so sanctioned types
   (JsonWebKey, NetCid, BCL) pass automatically.
2. `BackendAssemblies_AreActuallyReferenced_SoTheBlocklistIsMeaningful()` — canary: asserts each
   forbidden prefix matches at least one actually-referenced assembly, so a backend rename can't
   silently neuter the blocklist.
3. `Detector_FlagsBackendTypes_PositiveControl()` — proves the detector fires on direct/array/
   generic-nested backend types and does NOT fire on sanctioned ones.

For dataproofs adapt the prefixes (e.g. forbid `dotNetRDF`/`VDS.RDF` outside Rdfc, `System.Formats.Cbor`
outside Cose, `Microsoft.IdentityModel` types other than `JsonWebKey` in public API, per PRD §2.2).
No BannedSymbols.txt / BannedApiAnalyzers exists in ANY of the three repos (grepped; zero hits) —
"dependency hygiene" is done with the reflection test above, not Roslyn banned-symbols.

---

## 5. CI workflows

### 5.1 net-did `/Users/moises/Projects/net-did/.github/workflows/ci.yml` (verbatim)

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build-and-test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '10.0.x'

      - name: Restore dependencies
        run: dotnet restore

      - name: Build
        run: dotnet build --no-restore --configuration Release

      - name: Test
        run: dotnet test --no-build --configuration Release --verbosity normal --filter "Category!=NativeFFI"

  rust-audit:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-audit
        run: cargo install --locked cargo-audit

      # Documented remaining warning is RUSTSEC-2026-0097 (rand 0.8.5).
      # See native/zkryptium-ffi/README.md "Security audit" for reachability analysis.
      # Other advisories must not be introduced.
      - name: cargo audit (native FFI)
        working-directory: native/zkryptium-ffi
        run: cargo audit --ignore RUSTSEC-2026-0097
```

(The `rust-audit` job is net-did-specific native-FFI baggage — not applicable to dataproofs.)

### 5.2 net-did `/Users/moises/Projects/net-did/.github/workflows/publish.yml` (verbatim)

```yaml
name: Publish to NuGet

on:
  push:
    tags: ['v*']

jobs:
  publish:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '10.0.x'

      - name: Extract version from tag
        id: version
        run: echo "VERSION=${GITHUB_REF_NAME#v}" >> "$GITHUB_OUTPUT"

      - name: Restore dependencies
        run: dotnet restore

      - name: Build
        run: dotnet build --configuration Release -p:Version=${{ steps.version.outputs.VERSION }}

      - name: Test
        run: dotnet test --no-build --configuration Release --verbosity normal --filter "Category!=NativeFFI"

      - name: Pack
        run: dotnet pack --no-build --configuration Release -p:Version=${{ steps.version.outputs.VERSION }} --output ./nupkgs

      - name: Push to NuGet
        run: dotnet nuget push ./nupkgs/*.nupkg --source https://api.nuget.org/v3/index.json --api-key ${{ secrets.NUGET_API_KEY }} --skip-duplicate
```

Secret: `NUGET_API_KEY` (classic long-lived key).

### 5.3 didcomm `/Users/moises/Projects/didcomm-dotnet/.github/workflows/ci.yml` (verbatim — the recommended ci.yml shape)

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  build-test:
    name: build + test (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          global-json-file: global.json

      - name: Restore
        run: dotnet restore DidComm.sln

      - name: Build (warnings as errors — NFR-01)
        run: dotnet build DidComm.sln --configuration Release --no-restore /warnaserror

      - name: Test
        run: dotnet test DidComm.sln --configuration Release --no-build --logger "trx;LogFileName=test-results.trx" --collect "XPlat Code Coverage"

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: test-results-${{ matrix.os }}
          path: |
            **/TestResults/**/test-results.trx
            **/TestResults/**/coverage.cobertura.xml
          if-no-files-found: warn
```

Key conventions: `permissions: contents: read` (least privilege), OS matrix with
`fail-fast: false`, `setup-dotnet@v4` with `global-json-file: global.json` (pins to the repo's
global.json — preferable to `dotnet-version: 10.0.x`), explicit `.sln` argument, `/warnaserror`,
trx + cobertura artifacts.

### 5.4 didcomm `/Users/moises/Projects/didcomm-dotnet/.github/workflows/release.yml` (verbatim — the recommended publish.yml shape for a multi-package repo)

```yaml
name: Release

# NFR-08: on a version tag, build + test + pack all publishable packages and push them to
# NuGet.org. Tag the release as `vMAJOR.MINOR.PATCH` (e.g. v0.1.0); the package version is
# derived from the tag, overriding the dev-default DidCommVersion in Directory.Build.props.
#
# Prerequisite: add a repository secret named NUGET_API_KEY (a nuget.org API key scoped to push
# the DidComm.* package ids). Without it the push step fails — build/test/pack still validate.
on:
  push:
    tags:
      - 'v*'

permissions:
  contents: read

jobs:
  pack-and-publish:
    name: pack + publish to NuGet
    runs-on: ubuntu-latest
    # Gate the irreversible publish: add "Required reviewers" to the `nuget-release` environment
    # (repo Settings > Environments) so each tag push waits for approval before this job runs.
    # Until those rules exist this is a no-op. Scope the NUGET_API_KEY secret to this environment.
    environment: nuget-release
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          global-json-file: global.json

      - name: Derive version from tag
        id: version
        # Strip the leading 'v': refs/tags/v0.1.0 -> GITHUB_REF_NAME=v0.1.0 -> 0.1.0.
        run: echo "version=${GITHUB_REF_NAME#v}" >> "$GITHUB_OUTPUT"

      - name: Restore
        run: dotnet restore DidComm.sln

      - name: Build (warnings as errors — NFR-01)
        run: dotnet build DidComm.sln --configuration Release --no-restore /warnaserror -p:DidCommVersion=${{ steps.version.outputs.version }}

      - name: Test
        run: dotnet test DidComm.sln --configuration Release --no-build

      - name: Pack
        run: dotnet pack DidComm.sln --configuration Release --no-build -p:DidCommVersion=${{ steps.version.outputs.version }} --output artifacts

      - name: Upload packages artifact
        uses: actions/upload-artifact@v4
        with:
          name: nupkgs
          path: artifacts/*.*nupkg
          if-no-files-found: error

      - name: Push to NuGet.org
        # Pushes the .nupkg files; the matching .snupkg symbol packages ride along automatically.
        run: dotnet nuget push "artifacts/*.nupkg" --api-key "${{ secrets.NUGET_API_KEY }}" --source https://api.nuget.org/v3/index.json --skip-duplicate
```

Conventions: tag-driven `v*`, `environment: nuget-release` approval gate, `-p:DidCommVersion=`
override of the props default, pack whole solution (IsPackable=false projects skip themselves),
secret `NUGET_API_KEY`. didcomm also has `RELEASING.md` — a maintainer runbook documenting the
tag-driven flow ("Releases are tag-driven... gated behind a reviewer-approved environment").

### 5.5 crypto-dotnet workflows (structure — the FR-21 CI-gate precedent)

`/Users/moises/Projects/crypto-dotnet/.github/workflows/build.yml` (name: `build`): triggers
push→main + all PRs, `permissions: contents: read`. Job `build-test` matrix over
ubuntu/macos/windows: checkout → setup-dotnet (`dotnet-version: 10.0.x`) → cargo build native (n/a
for dataproofs) → `dotnet build NetCrypto.sln --configuration Release -warnaserror` →
`dotnet test ... --no-build --filter "Category!=BbsAbsent"` → **the two steps dataproofs FR-20/FR-21
must copy**:

```yaml
      # FR-17: every sample is executed and must exit 0 on all three OS legs.
      - name: Run all samples
        shell: bash
        run: |
          set -euo pipefail
          for proj in samples/*/; do
            echo "=== ${proj} ==="
            dotnet run --project "${proj}" --configuration Release --no-build
          done

      # FR-17 coverage check: every public type/member name must appear in samples/.
      - name: API coverage check
        shell: bash
        run: dotnet run --project tools/ApiCoverageCheck --configuration Release --no-build -- samples
```

`/Users/moises/Projects/crypto-dotnet/.github/workflows/release.yml` (name: `release`, tags `v*`):
mostly native-binary plumbing irrelevant to dataproofs, but two transferable conventions:
(a) version derivation `VERSION="${GITHUB_REF_NAME#v}"` then `dotnet pack ... -p:NetCryptoVersion="${VERSION}"`;
(b) **NuGet Trusted Publishing via OIDC** instead of a stored key — publish job has
`permissions: contents: write` (GitHub release) + `id-token: write`, then:

```yaml
      - name: NuGet login (OIDC → short-lived API key)
        id: nuget-login
        uses: NuGet/login@v1
        with:
          user: moisesja   # nuget.org account/profile name (public package owner), not an email

      - name: Push to NuGet (gated on all prior jobs)
        run: |
          dotnet nuget push artifacts/*.nupkg \
            --api-key "${{ steps.nuget-login.outputs.NUGET_API_KEY }}" \
            --source https://api.nuget.org/v3/index.json \
            --skip-duplicate
```

It also creates a GitHub release with `gh release create "${GITHUB_REF_NAME}" ... --generate-notes`
(env `GH_TOKEN: ${{ github.token }}`), and runs a `smoke` job that installs the packed nupkg from a
local-feed `nuget.config` into a fresh `dotnet new console` and runs it — a good model for
dataproofs AC-11's package-identity publish gate.

PRD §2.1 names the files `ci.yml` + `publish.yml` (net-did naming) — use those names but the
didcomm content shape, adding the crypto-dotnet samples + coverage steps to ci.yml.

---

## 6. samples/ conventions

Naming: one console project per topic, `<RootPackage>.Samples.<Topic>` (crypto:
`NetCrypto.Samples.Signing`, net-did: `NetDid.Samples.DidKey`). PRD §2.1 already prescribes
`DataProofsDotnet.Samples.*`. crypto-dotnet is the model the dataproofs PRD's FR-20 sample list
mirrors (10 focused samples + samples/README.md), not didcomm's single `02-Cookbook` app.

### 6.1 Sample csproj (verbatim — `/Users/moises/Projects/crypto-dotnet/samples/NetCrypto.Samples.Signing/NetCrypto.Samples.Signing.csproj`; net-did samples identical shape)

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <IsPackable>false</IsPackable>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="../../src/NetCrypto/NetCrypto.csproj" />
  </ItemGroup>
</Project>
```

No RootNamespace/AssemblyName overrides, no package refs — TFM/nullable/usings inherited from
Directory.Build.props.

### 6.2 Program.cs narration style (crypto-dotnet, the style to copy)

Top-level statements; banner comment; numbered `// ---` section dividers; `Console.WriteLine`
narration of every operation; self-checking via a local `Check` function so the sample doubles as a
CI smoke test. Excerpt from `samples/NetCrypto.Samples.Signing/Program.cs` (verbatim):

```csharp
using NetCrypto;

// ============================================================
// NetCrypto Samples — Signing
// ============================================================
// ICryptoProvider / DefaultCryptoProvider: Sign and Verify for
// every signing-capable KeyType, plus EcdsaSignatureFormat —
// the same P-256 key emitting DER and IEEE P1363 signatures.

// Code against the ICryptoProvider interface (not the concrete class) so the
// crypto backend can be swapped — e.g. for an HSM-backed provider — without
// touching any calling code. DefaultCryptoProvider is the stock software one.
ICryptoProvider crypto = new DefaultCryptoProvider();
...
Console.WriteLine("=== Sign / Verify per key type ===");
...
    Console.WriteLine($"  {keyType,-10}  sig {signature.Length,3} bytes  verify={valid}  tamperedVerify={tampered}");
    Check(valid, $"{keyType} signature verifies");
    Check(!tampered, $"{keyType} rejects tampered data");
```

and the closing pattern (verbatim):

```csharp
Console.WriteLine("Done! All signing examples completed successfully.");
return 0;

// Halt with a non-zero exit code on any failed expectation so an automated
// run of this sample (e.g. in CI) is marked as failed.
static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
```

### 6.3 samples/README.md (crypto-dotnet)

Header states the contract: "Small, self-contained console programs that demonstrate every public
surface of NetCrypto. Each sample is heavily commented, prints what it is doing, and **exits with
code 0 on success** (any assertion failure exits non-zero), so they double as smoke tests", with
`dotnet run --project samples/<Name>` usage, a `## Projects` table (project → what it demonstrates),
and a "## Start here — suggested reading order" section.

(didcomm alternative, for reference only: `samples/_shared/_shared.csproj` library + `Narrator`
class with `Section/Step/Value/Note` methods writing to an injectable `TextWriter`, and a cookbook
whose `Program.RunAsync(TextWriter?)` is invoked by an InteropTests smoke test without spawning a
process. Useful trick if dataproofs wants samples asserted in tests, but crypto's
run-every-`samples/*/`-in-CI loop is the FR-20 precedent.)

---

## 7. tasks/ tooling — the FR-21 samples-coverage tool (crypto-dotnet `tools/ApiCoverageCheck`)

**Full inventory: exactly two source files.** In crypto-dotnet it lives at `tools/ApiCoverageCheck/`
(NOT `tasks/`); dataproofs PRD §2.1 relocates it to `tasks/samples-coverage/`. It is a normal
console project added to the solution (so `--no-build` works in CI after `dotnet build <sln>`),
invoked as `dotnet run --project tools/ApiCoverageCheck --configuration Release --no-build -- samples`.

### 7.1 `/Users/moises/Projects/crypto-dotnet/tools/ApiCoverageCheck/ApiCoverageCheck.csproj` (verbatim)

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <IsPackable>false</IsPackable>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="../../src/NetCrypto/NetCrypto.csproj" />
  </ItemGroup>
</Project>
```

### 7.2 `/Users/moises/Projects/crypto-dotnet/tools/ApiCoverageCheck/Program.cs` (verbatim, complete — 87 lines)

```csharp
// FR-17 mechanical coverage check: reflects over the NetCrypto public API surface and
// verifies that every public type name and every public declared method/property name
// appears in at least one samples/**/*.cs file. CI fails (exit 1) on uncovered members.
using System.Reflection;
using System.Runtime.CompilerServices;

// FR-17: the exemption list MUST stay empty, or each entry must carry a
// written '// justification:' reviewed by the maintainer.
string[] exemptions =
[
];

// args[0]: path to the samples directory (default: 'samples' relative to the cwd).
string samplesDir = args.Length > 0 ? args[0] : "samples";
if (!Directory.Exists(samplesDir))
{
    Console.Error.WriteLine($"ERROR: samples directory not found: {Path.GetFullPath(samplesDir)}");
    return 2;
}

// Concatenate every sample source file; coverage is a simple substring check, which is
// deliberately loose — the goal is "the name shows up in the learning path", not parsing.
string samplesText = string.Concat(
    Directory.EnumerateFiles(samplesDir, "*.cs", SearchOption.AllDirectories)
        .OrderBy(p => p, StringComparer.Ordinal)
        .Select(File.ReadAllText));

// Member names inherited from System.Object / System.Enum / System.Delegate (and the
// serialization plumbing on System.Exception) never need a dedicated sample, even when
// a NetCrypto type overrides them.
string[] inheritedNames =
[
    "ToString", "Equals", "GetHashCode", "GetType", "ReferenceEquals", "MemberwiseClone",
    "CompareTo", "HasFlag", "GetTypeCode",                  // System.Enum
    "Invoke", "BeginInvoke", "EndInvoke", "DynamicInvoke",  // System.Delegate
    "GetObjectData", "GetBaseException",                    // System.Exception
];

var uncovered = new List<string>();

foreach (Type type in typeof(NetCrypto.KeyType).Assembly.GetExportedTypes()
             .OrderBy(t => t.FullName, StringComparer.Ordinal))
{
    // Generic types reflect as e.g. "Foo`1"; the source-visible name is "Foo".
    string typeName = type.Name.Split('`')[0];
    Require(typeName, typeName);

    if (type.IsEnum || typeof(Delegate).IsAssignableFrom(type))
        continue; // enum values and delegate Invoke signatures: only the TYPE name needs coverage.

    const BindingFlags declaredPublic =
        BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    foreach (MethodInfo method in type.GetMethods(declaredPublic))
    {
        // IsSpecialName drops property/event accessors and operators; constructors are not
        // in GetMethods; DeclaredOnly drops everything inherited from System.* base classes.
        if (method.IsSpecialName) continue;
        if (method.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false)) continue;
        if (inheritedNames.Contains(method.Name)) continue;
        Require($"{typeName}.{method.Name}", method.Name);
    }

    foreach (PropertyInfo property in type.GetProperties(declaredPublic))
    {
        if (property.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false)) continue;
        Require($"{typeName}.{property.Name}", property.Name);
    }
}

if (uncovered.Count == 0)
{
    Console.WriteLine($"API coverage OK: every public NetCrypto type/method/property name appears in {samplesDir}/**/*.cs.");
    return 0;
}

foreach (string entry in uncovered)
    Console.WriteLine($"UNCOVERED: {entry}");
Console.Error.WriteLine($"FAILED: {uncovered.Count} public API name(s) missing from {samplesDir}/**/*.cs (FR-17).");
return 1;

void Require(string label, string name)
{
    if (exemptions.Contains(label)) return;
    if (!samplesText.Contains(name, StringComparison.Ordinal))
        uncovered.Add(label);
}
```

Adaptation notes for dataproofs (FR-21): the anchor `typeof(NetCrypto.KeyType).Assembly` must become
**five** assembly anchors (one ProjectReference + one anchor type per package: Core, Jose, Cose,
Rdfc, Extensions.DependencyInjection), iterating
`new[] { typeof(...).Assembly, ... }.SelectMany(a => a.GetExportedTypes())`. Exit codes: 0 ok,
1 uncovered, 2 usage error. The exemption convention ("MUST stay empty, or each entry must carry a
written `// justification:`") maps directly to FR-21's "checked-in allowlist with a justification
comment". Note the check is name-substring based against sample SOURCE text — dataproofs FR-21 says
"statically analyzes the compiled samples"; the precedent is actually source-text substring matching,
which is simpler and is what "the FR-17 precedent from NetCrypto" concretely is.

### 7.3 Other tasks/ conventions

- Every repo keeps `tasks/lessons.md` (`# Lessons` header, entries `## L1 — <title>` with
  `**Context:**` paragraphs) and plan files `tasks/todo{timestamp}.md` (net-did:
  `todo20260603-123840.md`; didcomm: `todo20260601T191415Z.md`; crypto: `todo20260610T0815.md`).
  dataproofs already follows this (`tasks/todo20260611-1939.md`, `tasks/research/`).
- net-did `tools/` also holds `NetDid.Tools.WebVhCli` (repo-specific; pattern = non-packable
  console utilities live under `tools/`, but dataproofs PRD pins the coverage tool under
  `tasks/samples-coverage/`).
- No dependency-hygiene CLI tool and no BannedSymbols.txt anywhere; hygiene is the reflection test
  (§4) plus Directory.Packages.props comments ("must NOT appear in src/").

---

## 8. Test project conventions

Stack (identical across repos): **xunit 2.9.3** (v2, NOT v3) + `xunit.runner.visualstudio` (3.1.5
current) + `Microsoft.NET.Test.Sdk` (18.6.0 current) + **FluentAssertions 7.0.0 (pinned, license)** +
NSubstitute 5.3.0 + coverlet.collector.

Canonical test csproj — `/Users/moises/Projects/net-did/tests/NetDid.Core.Tests/NetDid.Core.Tests.csproj` (verbatim):

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <IsPackable>false</IsPackable>
    <IsTestProject>true</IsTestProject>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" />
    <PackageReference Include="xunit" />
    <PackageReference Include="xunit.runner.visualstudio" />
    <PackageReference Include="FluentAssertions" />
    <PackageReference Include="NSubstitute" />
    <PackageReference Include="coverlet.collector" />
  </ItemGroup>

  <ItemGroup>
    <ProjectReference Include="../../src/NetDid.Core/NetDid.Core.csproj" />
  </ItemGroup>

</Project>
```

Variations: didcomm adds `<RootNamespace>DidComm.Tests</RootNamespace>`,
`<AssemblyName>DidComm.Core.Tests</AssemblyName>`, `<GenerateDocumentationFile>false</GenerateDocumentationFile>`
(silences CS1591 under TreatWarningsAsErrors — dataproofs will need this if it adopts didcomm's
warnings-as-errors); crypto adds test-only package refs with a forbidden-in-src comment.

Organization: folders mirror the src feature areas, file-per-SUT named `<Thing>Tests.cs`
(e.g. didcomm `tests/DidComm.Core.Tests/{Crypto/{Aead,Kdf,KeyAgreement,KeyWrap},Envelopes/{Composition,
Encryption,Signing},Json,Integration,Consistency,...}`; crypto `tests/NetCrypto.Tests/{Crypto,
Encryption,Hashing,Jwk,KeyStore,DependencyInjection,NonFunctional}`). Cross-suite helpers go in a
separate non-test library project `tests/DidComm.TestSupport/` (IsPackable=false, referenced by
test projects AND samples — precedent for sharing fixtures). Interop/oracle tests are a separate
project `tests/DidComm.InteropTests/` with a `fixtures/` directory plus `FixtureCatalog.cs` /
`FixtureManifest.cs` / `FixtureDiscoveryTests.cs` (fixture files enumerated and asserted against a
manifest so unreferenced fixtures fail). Conditional/environment-dependent tests use
`[Trait("Category", "NativeFFI")]` / `[Trait("Category", "BbsAbsent")]` filtered in CI with
`--filter "Category!=X"`. No collection fixtures/IClassFixture convention dominates — plain
constructor-per-test classes.

`InternalsVisibleTo` lives in the library csproj as plain items:
`<ItemGroup><InternalsVisibleTo Include="NetCrypto.Tests" /></ItemGroup>` (didcomm lists 5: its two
test projects, DI package, adapter, TestSupport).

Library csproj shape (didcomm `src/DidComm.Core/DidComm.Core.csproj` pattern): PropertyGroup with
`RootNamespace` (didcomm uses bare `DidComm` for Core), `AssemblyName`, `PackageId`,
`<Version>$(DidCommVersion)</Version>`, `Description` (one sentence, mentions phase/spec);
PackageReferences carry rationale comments; `Microsoft.SourceLink.GitHub` always
`PrivateAssets="All"`.

---

## 9. Root docs (structure only)

- **AGENTS.md** — real file; **CLAUDE.md is a symlink to it** in all three repos. Sections:
  `# Agent & Contributor Instructions` → `## Project Overview` (one paragraph; crypto's includes the
  stack-layering ASCII diagram that already names dataproofs-dotnet) → `## Requirements and Design`
  (points at the PRD as "the main source of truth") → `## Workflow Orchestration` (Plan Mode /
  Subagents / Self-Improvement / Verification / Elegance / Autonomous Bug Fixing) → Task Management
  → Core Principles. dataproofs' existing AGENTS.md/CLAUDE.md already follow this.
- **CONTRIBUTING.md** — `# Contributing to <name>`; "spec-driven, PRD is normative" preamble
  (didcomm); `## Prerequisites` (.NET 10 SDK, Git, editor); `## Getting started` (clone/build/test
  shell block); `## Project structure` (annotated tree); `## Code style` (.editorconfig:
  file-scoped namespaces, 4-space indent); PR/test conventions. crypto-dotnet has none.
- **SECURITY.md** — `# Security Policy`; `## Supported versions` (table); `## Reporting a
  vulnerability` with bold "**Do not open a public GitHub issue for security vulnerabilities.**",
  "How to report" (didcomm points at GitHub private vulnerability reporting
  `https://github.com/moisesja/<repo>/security/advisories/new`), "What to expect"
  (ack ≤48h, remediation plan ≤7 days, credit); `## Scope` (in/out-of-scope areas). didcomm's
  opens by naming the security-critical crypto surfaces — mirror that for proofs.
- **CHANGELOG.md** — Keep a Changelog 1.1.0 + SemVer preamble; `## [x.y.z] - YYYY-MM-DD` sections
  with `### Added / Changed / Security / Fixed`; entries are **bold-titled paragraphs with issue
  refs** (`- **Title** (#71): prose...`), substantially more detailed than typical changelogs.
  crypto-dotnet has no CHANGELOG (pre-1.0).
- **RELEASING.md** (didcomm only) — maintainer runbook for the tag-driven NuGet release; worth
  copying given dataproofs' AC-11 publish gate.
- **README.md** — didcomm convention: "a thin router — don't add design or runbook content there."

---

## 10. Checklist of deltas the scaffold must decide (synthesis)

1. Version property name: `DataProofsVersion`, default e.g. `0.1.0` with the crypto-style
   `Condition="'$(DataProofsVersion)' == ''"` guard; every src csproj sets
   `<Version>$(DataProofsVersion)</Version>`; publish.yml passes `-p:DataProofsVersion=${TAG#v}`.
2. Solution file at root (`netdid.sln` / `DidComm.sln` / `NetCrypto.sln` precedent) — e.g.
   `DataProofsDotnet.sln`; CI invokes it explicitly.
3. ci.yml = didcomm shape (+`macos-latest` if desired; crypto uses all three) + crypto's
   "Run all samples" loop + "API coverage check" step pointing at `tasks/samples-coverage`
   (remember to add the tool project to the .sln so `--no-build` works).
4. publish.yml = didcomm release.yml shape (environment gate `nuget-release`, secret
   `NUGET_API_KEY`) — or crypto's OIDC `NuGet/login@v1` Trusted Publishing if no stored secret is
   wanted; crypto's local-feed smoke job is the AC-11 precedent.
5. PublicAPI.Shipped.txt/Unshipped.txt + `Microsoft.CodeAnalysis.PublicApiAnalyzers`
   `PrivateAssets="All"` + `<AdditionalFiles>` in EACH of the five src csprojs (crypto precedent).
6. ApiSurface.Tests = port `PublicApiHygieneTests` (blocklist + canary + positive control) with
   dataproofs' forbidden sets per PRD §2.2.
7. global.json: SDK `10.0.100`, `rollForward: latestFeature`; setup-dotnet with
   `global-json-file: global.json`.
8. CLAUDE.md should become a symlink to AGENTS.md to match the sibling repos (currently two files).
