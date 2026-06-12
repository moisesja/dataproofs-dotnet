# dataproofs-dotnet

Securing mechanisms for documents and credentials in .NET — the single home for both proof
families defined by the W3C and IETF securing-mechanism landscape.

| Package | What it gives you |
|---|---|
| `DataProofsDotnet.Core` | W3C VC Data Integrity 1.0: proof model, add/verify pipeline, cryptosuite registry, JCS suites (`eddsa-jcs-2022`, `ecdsa-jcs-2019`), verification-method resolver abstraction |
| `DataProofsDotnet.Jose` | JWS, JWE, JWT, JWK; SD-JWT (RFC 9901) with Key Binding; SD-JWT VC; VC-JOSE-COSE (JOSE half) |
| `DataProofsDotnet.Cose` | COSE_Sign1 (RFC 9052), CWT (RFC 8392), VC-JOSE-COSE (COSE half) |
| `DataProofsDotnet.Rdfc` | JSON-LD / RDFC-1.0 canonicalization, offline-default document loader, RDFC suites (`eddsa-rdfc-2022`, `ecdsa-rdfc-2019`), `bbs-2023` selective disclosure |
| `DataProofsDotnet.Extensions.DependencyInjection` | `AddDataProofs(...)` composition |

All cryptography routes through [NetCrypto](https://github.com/moisesja/crypto-dotnet); all
multiformats (multibase, multicodec, `Multikey`) and JCS through
[NetCid](https://github.com/moisesja/net-cid). Keys held in a NetCrypto `IKeyStore` are never
exported — every signing API accepts an `ISigner` or key-store alias, never raw private bytes.

## Getting started

```bash
git clone https://github.com/moisesja/dataproofs-dotnet.git
cd dataproofs-dotnet
dotnet build DataProofsDotnet.sln
dotnet test DataProofsDotnet.sln
```

Runnable, narrated examples for every feature live under [samples/](samples/) — each doubles as
a CI smoke test. Start with `samples/README.md`.

## Design documents

- [`dataproofs-concept.md`](dataproofs-concept.md) — vision and decisions log (binding)
- [`dataproofs-prd.md`](dataproofs-prd.md) — requirements; the main source of truth
- [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`SECURITY.md`](SECURITY.md) · [`CHANGELOG.md`](CHANGELOG.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
