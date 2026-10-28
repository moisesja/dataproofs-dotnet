# dataproofs-dotnet

Securing mechanisms for documents and credentials in .NET — the single home for both proof
families defined by the W3C and IETF securing-mechanism landscape.

| Package | What it gives you |
|---|---|
| `DataProofsDotnet.Core` | W3C VC Data Integrity 1.0: proof model, add/verify pipeline, cryptosuite registry, JCS suites (`eddsa-jcs-2022`, `ecdsa-jcs-2019`), verification-method resolver abstraction |
| `DataProofsDotnet.Jose` | JWS, JWE, JWT, JWK; SD-JWT (RFC 9901) with Key Binding; SD-JWT VC; VC-JOSE-COSE (JOSE half) |
| `DataProofsDotnet.Cose` | COSE_Sign1 (RFC 9052), CWT (RFC 8392), VC-JOSE-COSE (COSE half) |
| `DataProofsDotnet.Rdfc` | JSON-LD / RDFC-1.0 canonicalization, offline-default document loader, RDFC suites (`eddsa-rdfc-2022`, `ecdsa-rdfc-2019`), `bbs-2023` selective disclosure |
| `DataProofsDotnet.Legacy` | Pre–Data-Integrity Linked-Data-Signature suites (`Ed25519Signature2020`, `EcdsaSecp256r1Signature2019`), JCS + RDFC variants — **opt-in, for interop with existing corpora only** |
| `DataProofsDotnet.Extensions.DependencyInjection` | `AddDataProofs(...)` composition |

All cryptography routes through [NetCrypto](https://github.com/moisesja/crypto-dotnet); all
multiformats (multibase, multicodec, `Multikey`) and JCS through
[NetCid](https://github.com/moisesja/net-cid). Keys held in a NetCrypto `IKeyStore` are never
exported — signing accepts an `ISigner` or key-store alias, and JWE ECDH key agreement accepts an
opaque `IEcdhKey`, never raw private bytes.

## Getting started

```bash
git clone https://github.com/moisesja/dataproofs-dotnet.git
cd dataproofs-dotnet
dotnet build DataProofsDotnet.sln
dotnet test DataProofsDotnet.sln
```

Runnable, narrated examples for every feature live under [samples/](samples/) — each doubles as
a CI smoke test. Start with `samples/README.md`.

## RDFC canonicalization fails closed on data loss

JSON-LD processing drops what it cannot turn into RDF, and whatever it drops is not signed. So the
RDFC suites (`eddsa-rdfc-2022`, `ecdsa-rdfc-2019`, `bbs-2023`, and the Legacy RDFC variant) refuse
such input instead of signing less than the document says (VC Data Integrity 1.0 §2.4.3):

- Creating a proof throws `ProofGenerationException` with an inner `JsonLdDataLossException`.
- Verification fails with `DATA_LOSS_DETECTION_ERROR`.

Typical causes:

- **A term no `@context` defines.** credentials/v2 has no `@vocab`. Define your terms, or list
  `https://www.w3.org/ns/credentials/undefined-terms/v2` last, as VCDM 2.0 §5.2 requires. The offline
  loader bundles that context.
- **Proof terms no `@context` defines.** A credentials/v1 document also needs
  `https://w3id.org/security/data-integrity/v2`. The Legacy RDFC variant needs
  `https://w3id.org/security/suites/ed25519-2020/v1`. Both are bundled.
- **An IRI that is not well formed.** Examples: `?filter[id]=1`, a second `#`, a space, a relative IRI.
- **An IRI the canonical form would respell.** Examples: `/a/../b`, `%41`, `HTTPS://HOST`, `:443`.

Accepted input canonicalizes to the same bytes as before. See FR-9 in the PRD for the full rule.

## Native AOT and trimming

All six packages declare `IsAotCompatible`: they build with zero trim, single-file and AOT analyzer
warnings, and every System.Text.Json (de)serialization uses source-generated metadata, so they work in
trimmed and native-AOT applications and in .NET 10 file-based apps. CI job `ac-12` runs
[`tasks/aot-smoke`](tasks/aot-smoke/README.md), which exercises every package, under JIT, with
reflection-based serialization disabled, as a file-based app and as a native-AOT binary, and requires
byte-identical output from all four. As a consumer:

- `DataProofsJsonOptions.Default` serializes the library's own types through source-generated metadata
  in every host. For *your* types it falls back to reflection only where the host enables it. In a
  trimmed or AOT application, or any project with `PublishAot`, register them in your own
  `JsonSerializerContext`.
- `DataIntegrityProof` can be listed in your own context directly
  (`[JsonSerializable(typeof(DataIntegrityProof))]`); its `previousProof` converter is public for that
  reason.
- Publishing `Rdfc`, `Legacy` or the DI package with native AOT surfaces warnings from Newtonsoft.Json,
  dotNetRdf.Core's dependency, for `dynamic` support the RDFC path never reaches (`IL2104`/`IL3053`).
  Under `TreatWarningsAsErrors` they fail the publish; to keep them visible but not fatal, add
  `<WarningsNotAsErrors>$(WarningsNotAsErrors);IL2104;IL3053</WarningsNotAsErrors>`. That makes **every**
  dependency's collapsed trim/AOT warnings non-fatal, not only Newtonsoft.Json's, so check that each
  `IL2104`/`IL3053` in your publish log names `Newtonsoft.Json` and nothing else. Core, Jose and Cose
  produce no IL warnings.

## Design documents

- [`dataproofs-concept.md`](dataproofs-concept.md) — vision and decisions log (binding)
- [`dataproofs-prd.md`](dataproofs-prd.md) — requirements; the main source of truth
- [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`SECURITY.md`](SECURITY.md) · [`CHANGELOG.md`](CHANGELOG.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
