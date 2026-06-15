# DataProofsDotnet samples

Small, self-contained console programs that demonstrate every public surface of the five
`DataProofsDotnet.*` packages. Each sample is heavily commented, prints what it is doing, and
**exits with code 0 on success** — any failed expectation calls a local `Check(...)` that prints
`FAILED: …` and exits non-zero. So the samples double as smoke tests, and the
`tasks/samples-coverage` gate (FR-21 / AC-9) fails the build if any public member is exercised by
no sample.

Every sample except `Samples.DependencyInjection` constructs the library **by hand** — no
`AddDataProofs`, no DI container. That is deliberate (FR-22): the DI package *composes*, it never
hides the ability to wire things up manually. Sample 14 then shows the same objects assembled
through `AddDataProofs`.

All signing goes through a NetCrypto `ISigner` — never raw private-key bytes (AC-8). Several
samples drive a non-exporting `IKeyStore`-backed signer to make that concrete.

## Running

Run a single sample:

```sh
dotnet run --project samples/DataProofsDotnet.Samples.DataIntegrityJcs --configuration Release
```

Run every sample (the CI loop):

```sh
for proj in samples/DataProofsDotnet.Samples.*/; do
  dotnet run --project "$proj" --configuration Release
done
```

A non-zero exit from any sample marks the run as failed.

## Projects

| Sample | Demonstrates |
|---|---|
| `Samples.DataIntegrityJcs` | Sign + verify with `eddsa-jcs-2022` and `ecdsa-jcs-2019` (P-256 / P-384); resolver and raw-key verification; tamper / proofPurpose negatives. |
| `Samples.DataIntegrityRdfc` | `eddsa-rdfc-2022` / `ecdsa-rdfc-2019` over the offline document loader; the RDFC-1.0 canonicalizer directly (order-independence); the opt-in caching loader and fail-closed posture. |
| `Samples.DataIntegrityLegacy` | Opt-in pre–Data-Integrity suites `Ed25519Signature2020` / `EcdsaSecp256r1Signature2019` (`DataProofsDotnet.Legacy`): explicit registration, `type`-based dispatch (`SupportedProofTypes` / `GetByProofType`), JCS + RDFC variants; emits `type` with no `cryptosuite`. Interop only — prefer 2022/2019 for new proofs. |
| `Samples.ProofSetsAndChains` | Proof sets (independent co-signatures) and chains via `previousProof`, including the chain dependency property and a dangling-reference error. |
| `Samples.BbsSelectiveDisclosure` | `bbs-2023` issuer base proof → holder derived proof (mandatory + selective JSON pointers) → verifier; runs live where BBS native binaries are present, else prints a clear note and still exits 0. |
| `Samples.VerificationResolver` | Implementing `IVerificationMethodResolver`; full resolver-path verification with controller authorization — an authorized success and an unauthorized-method `INVALID_VERIFICATION_METHOD` failure. |
| `Samples.KeyStoreSigning` | A Data Integrity proof, a JWS, an SD-JWT (+KB-JWT), and a COSE_Sign1 — all produced from one non-exporting `IKeyStore` signer. |
| `Samples.Jws` | Compact and JSON (flattened / general / multi-signature) serialization, EdDSA and ES256K, detached payload, `Base64Url`. |
| `Samples.Jwe` | Multi-recipient JWE: `ECDH-ES+A256KW`, `ECDH-1PU+A256KW`, `A256KW`; A256GCM / A256CBC-HS512 / XC20P; peek, apu/apv. |
| `Samples.JwtAndJwk` | JWT claims validation (exp/nbf/iat/iss/aud/sub + clock skew, structured results); JWK ↔ Multikey conversion; RFC 7638 thumbprints / `kid`. |
| `Samples.SdJwt` | SD-JWT issuance with flat / structured / recursive / array-element disclosures and decoy digests; holder presentation; KB-JWT. |
| `Samples.SdJwtVc` | The SD-JWT VC profile end to end: `vct` rules, `dc+sd-jwt` media type, must-not-disclose claims, offline Type Metadata resolution. |
| `Samples.CoseCwt` | COSE_Sign1 for every v1 algorithm (detached payload, external AAD, tag control) and a CWT round trip with exp/nbf validation. |
| `Samples.VcJoseCose` | Enveloping a VCDM 2.0 credential — the JOSE half (`vc+jwt`) and the COSE half (`application/vc+cose`). |
| `Samples.DependencyInjection` | Composing the pipeline, suites, the enveloping families, and a caller-supplied resolver through `AddDataProofs`. The only sample that uses the DI package. |

## Start here — suggested reading order

1. **`Samples.DataIntegrityJcs`** — the embedded-proof pipeline at its simplest (sign → verify).
2. **`Samples.DataIntegrityRdfc`** — the same pipeline over RDF canonicalization and the offline loader.
3. **`Samples.DataIntegrityLegacy`** — opt-in pre–Data-Integrity LD-Signature suites and `type`-based dispatch (interop).
4. **`Samples.VerificationResolver`** — how verification authorizes a method against a controller (FR-3/FR-7).
5. **`Samples.ProofSetsAndChains`** — multiple proofs on one document.
6. **`Samples.BbsSelectiveDisclosure`** — selective disclosure with BBS.
7. **`Samples.Jws`** → **`Samples.Jwe`** → **`Samples.JwtAndJwk`** — the JOSE enveloping family.
8. **`Samples.SdJwt`** → **`Samples.SdJwtVc`** — selective disclosure in JSON and its VC profile.
9. **`Samples.CoseCwt`** → **`Samples.VcJoseCose`** — the CBOR side and the VC-JOSE-COSE binding.
10. **`Samples.KeyStoreSigning`** — every family from one non-exporting key store (AC-8).
11. **`Samples.DependencyInjection`** — assemble all of the above through `AddDataProofs`.
