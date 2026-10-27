# aot-smoke (AC-12)

This is the run-time half of PRD **NFR-7** (native AOT and trimming, issue
[#27](https://github.com/moisesja/dataproofs-dotnet/issues/27)).

The compile-time half is `IsAotCompatible` on every package. Its trim, single-file and AOT analyzer
warnings are fatal under the repo-wide warnings-as-errors. But those analyzers only see annotated
code. dotNetRdf.Core, Newtonsoft.Json, NetCrypto, NetCid and Microsoft.IdentityModel.Tokens are not
annotated. This tool runs every package's main paths under native AOT and checks two things: the
output is byte-identical to JIT, and the native compile reports no IL warning nobody has reviewed.

It already earned its place once. NetCid's `JcsCanonicalizer.Canonicalize(JsonNode)` overloads
serialize through reflection-based System.Text.Json. In an AOT host, every JCS proof carrying
`@context` therefore failed to verify, and the packages' own build reported nothing. The tool's first
reflection-disabled run found it. The ILCompiler also reports it, as a NetCid warning in the publish
log, which is why the IL scan below fails on *any* warning not on its known list. The JCS suite now
canonicalizes a `JsonElement`, and `BannedSymbols.txt` bans the four `JsonNode` overloads.

## What it exercises

Every path uses fixed seed keys, fixed timestamps and fixed documents (`Fixtures.cs`).

| Path | Covers |
| --- | --- |
| `JcsPath` | `eddsa-jcs-2022` and `ecdsa-jcs-2019` through `DataIntegrityProofPipeline`, with raw-key and resolver verification. A two-proof chain with an array-form `previousProof`. |
| `RdfcPath` | RDFC-1.0 through dotNetRdf for an inline-`@context` document with blank nodes. A VC v2 document whose context comes from the **offline** loader. `eddsa-rdfc-2022` and `ecdsa-rdfc-2019`. |
| `Bbs2023Path` | `bbs-2023` base proof, derived proof with mandatory and selective pointers, and verification. **Required** on every RID for which NetCrypto ships the native BBS library: osx-arm64, osx-x64, linux-x64, linux-arm64 and win-x64. Elsewhere it is recorded as unavailable and skipped. |
| `LegacyPath` | `Ed25519Signature2020` and `EcdsaSecp256r1Signature2019`, each in the JCS and RDFC variants. The RDFC signing input is the one zcap-dotnet uses. |
| `JosePath` | JWS in compact, Flattened, General and DIDComm kid-placement forms; JWT with claim validation; General JSON JWE with ECDH-ES+A256KW and A256KW; compact JWE. |
| `SdJwtPath` | SD-JWT issuance with object and array-element disclosures and decoys, then a holder presentation with a Key Binding JWT, then verification. |
| `CoseAndVcPath` | COSE_Sign1 with EdDSA and ES256, CWT, and the VC-JOSE and VC-COSE envelopes. |
| `JwkPath` | JWK to and from Multikey, conversion to `Microsoft.IdentityModel.Tokens.JsonWebKey`, the `PublicKeyMaterial` JWK round trip, and RFC 7638 thumbprints. |
| `CompositionPath` | `AddDataProofs` with every registration. A consumer `JsonSerializerContext` that lists `DataIntegrityProof` (the zcap-dotnet#154 scenario, `AotSmokeJson.cs`). Resolution through `DataProofsJsonOptions.Default`. |

The tool itself never calls a reflection-based serializer overload. Its own analyzers are on, so such
a call does not compile. An exception escaping a path is reported as a failed expectation.

## Modes

```
AotSmoke emit <report.json>                run every path, self-verify each output, write the report
AotSmoke verify <report.json>              verify another run's outputs with the same keys
AotSmoke compare <a.json> <b.json> [...]   the deterministic sections must be identical
```

Exit code `0` means success, `1` means a failed expectation (printed as `FAILED: …`), and `2` means
bad usage. The report has three sections:

- **`runtime`** describes the host and is never compared. It records dynamic-code support, the
  reflection switch, the RID, the framework, BBS availability, and whether `DataProofsJsonOptions.Default`
  resolved a consumer type.
- **`deterministic`** must be byte-identical across runtimes. It holds canonical N-Quads, JCS bytes,
  EdDSA proofs and envelopes, header encodings, the bbs-2023 base proof, thumbprints and the
  registered suites.
- **`artifacts`** holds the randomized outputs, which `verify` checks from another run: ECDSA proofs,
  JWEs, the SD-JWT presentation and the bbs-2023 derived proof.

## The four legs

| Leg | How | Runtime it proves |
| --- | --- | --- |
| JIT | `dotnet build -o jit` then `dotnet jit/AotSmoke.dll` | an ordinary application: dynamic code on, reflection on |
| Reflection disabled | build with `-p:JsonSerializerIsReflectionEnabledByDefault=false` | the serializer condition of a trimmed host |
| File-based app | `dotnet run file-based-app/aot-smoke.cs` (`#:project ../AotSmoke.csproj`) | a .NET 10 file-based app: the SDK's native-AOT defaults under `dotnet run`, with dynamic code and reflection both off |
| Native AOT | `dotnet publish -r <rid> -p:PublishAot=true` | a native binary |

```bash
S=$(mktemp -d)
dotnet build tasks/aot-smoke -c Release -o "$S/jit" && dotnet "$S/jit/AotSmoke.dll" emit "$S/jit.json"
dotnet build tasks/aot-smoke -c Release --no-incremental -p:JsonSerializerIsReflectionEnabledByDefault=false -o "$S/noreflect"
dotnet "$S/noreflect/AotSmoke.dll" emit "$S/trimmed.json"
dotnet run tasks/aot-smoke/file-based-app/aot-smoke.cs -c Release -- emit "$S/filebased.json"
dotnet publish tasks/aot-smoke -c Release -r osx-arm64 -p:PublishAot=true -o "$S/aot" > "$S/publish.log"   # needs clang; use your RID
"$S/aot/AotSmoke" emit "$S/aot.json"
dotnet "$S/jit/AotSmoke.dll" compare "$S/jit.json" "$S/trimmed.json" "$S/filebased.json" "$S/aot.json"
"$S/aot/AotSmoke" verify "$S/jit.json" && dotnet "$S/jit/AotSmoke.dll" verify "$S/aot.json"
bash tasks/aot-smoke/scan-il-warnings.sh --self-test && bash tasks/aot-smoke/scan-il-warnings.sh "$S/publish.log"
```

`PublishAot` is passed on the command line, not set in `AotSmoke.csproj`, for two reasons. Ordinary
solution restores then never download the ILCompiler packages. And the JIT leg stays a true JIT
baseline, because in a project that sets `PublishAot` the SDK turns `IsReflectionEnabledByDefault` off
even under `dotnet run`. `IlcTreatWarningsAsErrors=false` keeps the known Newtonsoft.Json warnings
from failing the publish. The scan, not the compiler's exit code, decides whether a warning is
acceptable. The tool's own Roslyn analyzers remain errors.

## The IL-warning scan

`scan-il-warnings.sh <publish.log>` fails in three cases:

- the log is missing or empty;
- the log shows no native compilation (`Generating native code`), as with a publish that was skipped
  as up to date;
- any `IL2xxx`/`IL3xxx` line does not contain an entry of `known-il-warnings.txt`.

The known list names each warning's code and member, with the reason it is unreachable. Today it
holds only Newtonsoft.Json's `dynamic` support and `JValue.IConvertible.ToType`, which dotNetRdf's
JSON-LD parser never takes. `--self-test` proves the scan rejects a DataProofs warning, an unknown
dependency warning (the NetCid case), a log without native compilation, and an empty or missing log,
and accepts a known warning.

If `ac-12` reports a new warning, trace it before touching the list. If the path is reachable, stop
using it and ban it in `BannedSymbols.txt` with the reason. Only a warning shown to be unreachable goes
on the list.

## The CI job (`ac-12` in `.github/workflows/ci.yml`)

On ubuntu-latest, the job runs the four legs for linux-x64. It asserts each report's `runtime` block
matches the leg that produced it, so a mix-up cannot pass. It runs `compare` across all four reports
and cross-`verify` between runtimes, then runs the scan's self-test and the scan. The reports and the
publish log are uploaded as the `aot-smoke-reports` artifact.
