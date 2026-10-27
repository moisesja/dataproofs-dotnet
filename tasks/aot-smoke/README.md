# aot-smoke (AC-12)

The run-time half of PRD **NFR-7** (native AOT and trimming, issue
[#27](https://github.com/moisesja/dataproofs-dotnet/issues/27)). The compile-time half is
`IsAotCompatible` on every package, whose trim, single-file and AOT analyzer warnings the
repo-wide warnings-as-errors makes fatal. The analyzers only see annotated code: dotNetRdf.Core,
Newtonsoft.Json, NetCrypto, NetCid and Microsoft.IdentityModel.Tokens are not annotated, so only
running the code under native AOT proves it. This tool does that, and checks that the output is
byte-identical to JIT.

It already earned its place once. Its first reflection-disabled run found that NetCid's
`JcsCanonicalizer.Canonicalize(JsonNode)` overloads serialize through reflection-based
System.Text.Json, so every JCS proof carrying `@context` failed to verify in an AOT host, with no
analyzer warning. The JCS suite now canonicalizes a `JsonElement`, and `BannedSymbols.txt` bans the
four `JsonNode` overloads.

## What it exercises

Every path uses fixed seed keys, fixed timestamps and fixed documents (`Fixtures.cs`).

| Path | Covers |
| --- | --- |
| `JcsPath` | `eddsa-jcs-2022` and `ecdsa-jcs-2019` through `DataIntegrityProofPipeline`, raw-key and resolver verification, and a two-proof chain with an array-form `previousProof`. |
| `RdfcPath` | RDFC-1.0 through dotNetRdf for an inline-`@context` document with blank nodes, and for a VC v2 document whose context comes from the **offline** loader. Also `eddsa-rdfc-2022` and `ecdsa-rdfc-2019`. |
| `Bbs2023Path` | `bbs-2023` base proof, derived proof with mandatory and selective pointers, and verification. **Required** on osx-arm64 and linux-x64, where NetCrypto ships the native BBS library. Elsewhere it is recorded as unavailable and skipped. |
| `LegacyPath` | `Ed25519Signature2020` with JCS and RDFC, and `EcdsaSecp256r1Signature2019` with RDFC. The RDFC signing input is the one zcap-dotnet uses. |
| `JosePath` | Compact, Flattened, General and DIDComm-placement JWS; JWT with claim validation; General JSON JWE with ECDH-ES+A256KW and A256KW; compact JWE. |
| `SdJwtPath` | SD-JWT issuance with object and array-element disclosures and decoys, a holder presentation with a Key Binding JWT, and verification. |
| `CoseAndVcPath` | COSE_Sign1 with EdDSA and ES256, CWT, and the VC-JOSE and VC-COSE envelopes. |
| `JwkPath` | JWK to and from Multikey, conversion to `Microsoft.IdentityModel.Tokens.JsonWebKey`, the `PublicKeyMaterial` JWK round trip, and RFC 7638 thumbprints. |
| `CompositionPath` | `AddDataProofs` with every registration. A consumer `JsonSerializerContext` that lists `DataIntegrityProof` (the zcap-dotnet#154 scenario, `AotSmokeJson.cs`). Resolution through `DataProofsJsonOptions.Default`. |

The tool itself never calls a reflection-based serializer overload. Its own analyzers are on, so
such a call would not compile.

## Modes

```
AotSmoke emit <report.json>                run every path, self-verify each output, write the report
AotSmoke verify <report.json>              verify another run's outputs with the same keys
AotSmoke compare <a.json> <b.json> [...]   the deterministic sections must be identical
```

Exit code `0` means success, `1` means a failed expectation (printed as `FAILED: …`), and `2`
means bad usage. The report has three sections:

- `runtime`: dynamic-code support, the reflection switch, RID, framework, BBS availability, and
  whether `DataProofsJsonOptions.Default` resolved a consumer type. These describe the host and are
  never compared.
- `deterministic`: canonical N-Quads, JCS bytes, EdDSA proofs and envelopes, header encodings, the
  bbs-2023 base proof, thumbprints and registered suites. These must be byte-identical across
  runtimes.
- `artifacts`: randomized outputs (ECDSA proofs, JWEs, the SD-JWT presentation, the bbs-2023
  derived proof). `verify` checks them from another run.

## Running it locally

```bash
S=$(mktemp -d)
# 1. JIT, reflection-based serialization enabled (an ordinary application)
dotnet build tasks/aot-smoke -c Release -o "$S/jit"
dotnet "$S/jit/AotSmoke.dll" emit "$S/jit.json"
# 2. JIT, reflection-based serialization disabled (trimmed hosts and .NET 10 file-based apps)
dotnet build tasks/aot-smoke -c Release --no-incremental -p:JsonSerializerIsReflectionEnabledByDefault=false -o "$S/noreflect"
dotnet "$S/noreflect/AotSmoke.dll" emit "$S/trimmed.json"
# 3. Native AOT (needs clang; use your RID)
dotnet publish tasks/aot-smoke -c Release -r osx-arm64 -p:PublishAot=true -o "$S/aot" | tee "$S/publish.log"
"$S/aot/AotSmoke" emit "$S/aot.json"
# Parity and cross-verification
dotnet "$S/jit/AotSmoke.dll" compare "$S/jit.json" "$S/trimmed.json" "$S/aot.json"
"$S/aot/AotSmoke" verify "$S/jit.json"
dotnet "$S/jit/AotSmoke.dll" verify "$S/aot.json"
```

`PublishAot` is passed on the command line, not set in `AotSmoke.csproj`, for two reasons.
Ordinary solution restores then never download the ILCompiler packages. And the first leg stays a
true JIT baseline, because in a project that sets `PublishAot` the SDK turns
`IsReflectionEnabledByDefault` off even under `dotnet run`.

## The CI job (`ac-12` in `.github/workflows/ci.yml`)

On ubuntu-latest, the job runs the three legs above for linux-x64. It asserts each report's
`runtime` block matches the leg that produced it, so a mix-up cannot pass. It runs `compare` across
all three reports and cross-`verify` in both directions. It then scans the publish log for
`IL2xxx`/`IL3xxx` warnings attributed to a `DataProofsDotnet` assembly or a `src/` path, with a
positive control that plants a matching line and requires the scan to fire. Third-party warnings
are printed but are not fatal. The reports and the publish log are uploaded as the
`aot-smoke-reports` artifact.
