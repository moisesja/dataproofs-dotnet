# DataProofsDotnet — Product Requirements Document

**Repository:** `dataproofs-dotnet` · **Packages:** `DataProofsDotnet.Core`, `.Jose`, `.Cose`, `.Rdfc`, `.Legacy`, `.Extensions.DependencyInjection` · **Status:** Draft v1 · **Date:** 2026-06-10
**Parent document:** `dataproofs-concept.md` (approved 2026-06-10). The concept's decisions log (D1–D7) is binding; this PRD does not reopen it.

---

## 1. Overview and scope

### 1.1 Goal

Ship the proof layer of the stack: a five-package library that produces and verifies **embedded proofs** (W3C Data Integrity with five cryptosuites) and **enveloping proofs** (JWS/JWE/JWT/JWK, SD-JWT with Key Binding, SD-JWT VC, COSE_Sign1/CWT, and the VC-JOSE-COSE binding), with all cryptography routed through NetCrypto and all multiformats/JCS through NetCid.

### 1.2 Scope boundary (hard rule)

The scope of this PRD ends at the published, fully verified `DataProofsDotnet.*` packages.

- **In scope:** everything inside the `dataproofs-dotnet` repository; **porting code and tests** *from* the sibling libraries that contain proven, relevant implementations — `didcomm-dotnet` (enveloping/JOSE) and `zcap-dotnet` (embedded/Data Integrity) — adapted per §1.4; **leveraging `net-did`'s relevant work** per §1.4 — its `DataIntegrityProof` proof-record model reconciled into `Core` (copy-in-scope), and its `did:key`/`did:peer`/`did:webvh` resolution leveraged at net-did's own composition layer via the resolver interface (§8), since this library must not reference `net-did` or hard-code `did:key`; dev-time use of `jose-jwt` and `Owf.Sd.Jwt` as interop oracles in the test project.
- **Out of scope:** any change to the `net-did`, `didcomm-dotnet`, `zcap-dotnet`, or `crypto-dotnet` repositories — sibling repos are read-only sources here; their adoption of this library is separately tracked (concept §8) and sequenced after v1 ships.

### 1.3 Definition of done

All five packages published to NuGet at v1.0.0 with every acceptance criterion in §9 green in CI — which now includes **AC-11 (package identity & publish readiness):** the five `DataProofsDotnet.*` IDs are confirmed available-and-claimable or already owned, and the `DataProofsDotnet` ID prefix is reserved to the owner, before first publish. No downstream repository work is part of done.

### 1.4 Reference implementations and porting sources

The ecosystem already contains substantial conformant work; this library **maximizes reuse of it** rather than rebuilding. Reuse takes the form appropriate to each source's conformance and coupling — the two families each have a proven sibling implementation to port, adapted as noted. Agents MUST consult these before writing new code, in this order of authority. (Confirmed by source audit on 2026-06-10.)

**1. `zcap-dotnet` (`ZcapLd.Core`) — porting source for the embedded-proof (Data Integrity) family.** It already implements, in conformant form, much of `Core` + `Rdfc`: a cryptosuite provider (`ICryptoSuiteProvider`/`CryptoSuiteProvider`), a canonicalizer abstraction with both JCS and RDFC implementations behind `IDocumentCanonicalizer`/`DocumentCanonicalizerProvider`, a `ProofSigningPayloadBuilder` that performs the spec-correct `SHA-256(canonicalProofConfig) ‖ SHA-256(canonicalDocument)` hash-concat (RDFC path) with proof options carrying `@context` and excluding `proofValue`, `Proof`/`ProofSet` models, a `SignatureVerifier` with a structured `SignatureResult`, a `CachedContextLoader`, and a `MultibaseCodec`. **Port these — with one exception: `MultibaseCodec` is reference only (see the NetCid adaptation below) — and preserve the conformant mechanics.** Required adaptations on port (each is a porting-task acceptance item, not optional):
   - **Generalize the document type.** zcap operates on ZCAP-specific `Capability`/`Invocation`; lift the pipeline to arbitrary JSON-LD documents (FR-2).
   - **Update to the 2022/2019 cryptosuite generation.** zcap targets the 2020-era suites (`Ed25519Signature2020`, `EcdsaSecp256r1Signature2019`, `type: "Ed25519Signature2020"`, the `…/suites/ed25519-2020/v1` context). dataproofs targets `DataIntegrityProof` + a `cryptosuite` field with `eddsa-jcs-2022`/`ecdsa-jcs-2019`/`eddsa-rdfc-2022`/`ecdsa-rdfc-2019`. **Critically, zcap's JCS path signs the document with the proof embedded (the 2020 convention); `eddsa-jcs-2022` requires the same separate-proof-config canonicalization + hash-concat that zcap already applies on its RDFC path** — extend that mechanic to the JCS suites (FR-5). zcap's RDFC hash-concat transfers directly (FR-11).
   - **Reroute crypto through NetCrypto.** zcap's `ICryptoSuite.Sign(byte[] data, byte[] privateKey)` takes a raw private key and delegates to NetDid's `DefaultCryptoProvider` (with `EcdsaSignatureFormat.IeeeP1363` — retain that P1363 detail; it is W3C-correct). Replace with NetCrypto `ISigner` so an `IKeyStore`-held key is never exported (AC-8), and replace the NetDid crypto dependency entirely.
   - **Multiformats come from NetCid, not ported.** zcap's `MultibaseCodec` is **reference only**: multibase, multicodec, and multihash are owned by NetCid stack-wide (concept §1.2), and `net-cid` already ships `Multikey` and the multicodec mappings. All base58-btc / multibase encoding of `proofValue` and key material routes through NetCid's APIs — no local multibase/multicodec implementation ships in `DataProofsDotnet`.
   - **Re-split along the package boundary.** zcap keeps dotNetRDF in its `Core`; here the RDFC canonicalizer and RDFC suites go in `Rdfc` (sole dotNetRDF reference, §2.2) while the JCS canonicalizer and JCS suites stay in `Core`.
   - **Test treatment.** zcap's Data Integrity tests *guide* the port but are **not** transferred as verbatim parity (suite identifiers and models change); conformance of the ported pipeline is pinned to the W3C test vectors of **AC-1**, not to zcap's assertions.

**2. `didcomm-dotnet` (`src/DidComm.Core/Jose/`) — porting source for the enveloping-proof (JOSE) family.** ~1,100 lines of proven JWS/JWE (builders, parsers, protected headers, APU/APV computation, recipient key wrap, Concat-KDF), plus directly relevant `Jwk.cs`, `JwkConversion.cs`, and `Base64Url.cs`. Port the code **and its tests**, preserving test assertion content — for JOSE the algorithms and envelopes are unchanged, so this is a true behavior-parity port (**AC-5**). Reroute crypto to NetCrypto; keep the JWK↔key conversion. Additionally, `didcomm-dotnet`'s resolver-adapter pattern — `ISecretsResolver` defined in core with a separate `DidComm.Adapters.NetDid` project implementing it — is the **precedent for FR-7**: the `IVerificationMethodResolver` interface lives here; a net-did-backed implementation lives in an adapter owned outside this repo.

**3. `net-did` (`src/NetDid.Core/Crypto/DataIntegrity/` + DID-method parsing) — source for the proof-record model and verification-method resolution.** net-did's relevant work is leveraged in the forms the dependency rules require, each placed at the correct layer:
   - **Proof-record model — copied into `Core` (FR-1).** net-did carries the modern `DataIntegrityProof` shape (`type: DataIntegrityProof` + named `cryptosuite`), which zcap's 2020-era models (`Ed25519Signature2020`) predate; net-did's record shape is therefore the stronger model reference for FR-1 and is reconciled into `Core`'s proof model.
   - **DID resolution — leveraged downstream, not copied here (FR-7, §8).** net-did's `did:key`/`did:peer`/`did:webvh` parsing (`ExtractDidKeyMultibase`/`ExtractPublicKeyFromDidKey` and the per-method handlers) is substantial, tested work. It is leveraged as the concrete implementation behind the `IVerificationMethodResolver` that net-did supplies at the composition layer — *not* copied into `Core`, because the dependency rules forbid this library hard-coding `did:key` or referencing `net-did`. Composing it at net-did's own layer is precisely how the stack reuses this work without inverting the dependency arrow.
   - **`eddsa-jcs-2022` engine — identifier/encoding reference.** net-did's engine signs the JCS-canonicalized document bytes directly with no proof-configuration hashing and is single-suite, so its structure is a useful reference for that suite's identifiers and encoding, but the conformant `SHA-256(canonicalProofConfig) ‖ SHA-256(canonicalDocument)` hash-concat is taken from the zcap port (item 1), not from net-did. Whether net-did's engine meets the did:webvh requirement is tracked in that repository's backlog.

**4. Governing specifications and their test vectors** (concept §2) — the source of truth; wherever a porting source and a spec disagree, the spec wins (this is exactly why zcap's 2020-convention JCS path is adapted, not copied verbatim).

**5. Interop oracles** — `jose-jwt` and `Owf.Sd.Jwt` as dev-dependencies of the test project only (never any `src/` project), for cross-verification fixtures (AC-3).

---

## 2. Repository and package structure

### 2.1 Layout

Mirrors the `net-did`/`didcomm-dotnet` conventions: .NET 10, `Directory.Build.props` + `Directory.Packages.props` (central package management), `global.json`, `src/`, `tests/`, `samples/`, `tasks/`, `docs/`, `AGENTS.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, CI via `.github/workflows/ci.yml` + `publish.yml`.

```
src/
  DataProofsDotnet.Core/
  DataProofsDotnet.Jose/
  DataProofsDotnet.Cose/
  DataProofsDotnet.Rdfc/
  DataProofsDotnet.Legacy/            (opt-in pre–Data-Integrity LD-Signature suites)
  DataProofsDotnet.Extensions.DependencyInjection/
tests/
  DataProofsDotnet.Core.Tests/
  DataProofsDotnet.Jose.Tests/        (includes ported didcomm parity suite + oracle cross-checks)
  DataProofsDotnet.Cose.Tests/
  DataProofsDotnet.Rdfc.Tests/        (includes W3C interop fixtures)
  DataProofsDotnet.Legacy.Tests/      (includes zcap cross-stack golden vector)
  DataProofsDotnet.ApiSurface.Tests/  (public-API + dependency-hygiene gates)
samples/
  DataProofsDotnet.Samples.*          (FR-20)
tasks/
  samples-coverage/                   (FR-21 tooling)
```

### 2.2 Package dependency rules (mechanically enforced, AC-6)

| Package | May reference |
|---|---|
| `Core` | NetCrypto, NetCid, `Microsoft.IdentityModel.Tokens` (JWK exception — only the `JsonWebKey` type may appear in public API; AC-7), BCL |
| `Jose` | `Core` |
| `Cose` | `Core`, `System.Formats.Cbor` |
| `Rdfc` | `Core`, dotNetRDF (sole reference in the entire stack) |
| `Legacy` | `Core`, `Rdfc` (the RDFC variant needs `IRdfCanonicalizer`; dotNetRDF arrives transitively via the `Rdfc` project reference only — no direct dotNetRDF package reference, so the hygiene gate stays satisfied) |
| `Extensions.DependencyInjection` | all of the above, `Microsoft.Extensions.DependencyInjection.Abstractions` |

Forbidden everywhere: `net-did` packages, `jose-jwt`, SdJwt.Net (runtime), NSec, NBitcoin.Secp256k1, Nethermind.* — crypto arrives only through NetCrypto. **This includes hashing:** no direct use of `System.Security.Cryptography` cryptographic primitives anywhere in `src/` — hashes (`SHA256`/`SHA384`/`SHA512`/`SHA3_*`), HMACs, signature algorithms (`ECDsa`, `RSA`, `ECDsaOpenSsl`, …), or AEADs (`AesGcm`, `AesCcm`, `ChaCha20Poly1305`). Every hash the suites, the proof hash-concat, JWK thumbprints (FR-15), and SD-JWT/KB-JWT digests need is taken from NetCrypto's hashing API (`NetCrypto.Hash` — `Sha256`/`Sha384`/`Sha512` — plus `Keccak256`, `Hkdf`, `ConcatKdf`), and every AEAD/key-wrap from NetCrypto's cipher statics (`AesGcmCipher`, `AesCbcHmacCipher`, `XChaCha20Poly1305Cipher`, `AesKeyWrap`). The sole allowlisted `System.Security.Cryptography` symbol is `CryptographicOperations.FixedTimeEquals` (a comparison utility, not a keyed/algorithmic primitive; NFR-6). `System.Formats.Cbor` is not in this namespace and remains allowed (`Cose`). If a primitive is missing, it is a NetCrypto work item, not a local shim (concept §6). Enforced by AC-6.

---

## 3. Functional requirements — Core (embedded proofs)

**FR-1 — Proof model.** A `DataIntegrityProof` type modeling the full VC Data Integrity 1.0 proof: `type` (`DataIntegrityProof`), `cryptosuite`, `created`, `expires`, `verificationMethod`, `proofPurpose`, `challenge`, `domain`, `nonce`, `previousProof` (string or set), `proofValue`. `System.Text.Json` (de)serialization with spec-correct member names and omission of nulls. *Port reference:* zcap-dotnet's `Proof`/`ProofSet` and JSON converters (`ZcapJsonOptions`), updated to the `DataIntegrityProof` + `cryptosuite` generation per §1.4.

**FR-2 — Proof pipeline.** A cryptosuite-agnostic engine implementing the Add Proof and Verify Proof algorithms of VC Data Integrity 1.0: proof-options validation, transformation, hashing, proof serialization (signing), `proofValue` encoding, and the inverse for verification — delegating the suite-specific steps to registered cryptosuites (FR-4). Signing goes through NetCrypto `ISigner` (async, `CancellationToken`); a signer backed by a non-exporting `IKeyStore` MUST be sufficient for every suite. *Porting source:* zcap-dotnet's `ProofSigningPayloadBuilder` + `SignatureVerifier`/`SignatureResult`, generalized from `Capability`/`Invocation` to arbitrary documents and rerouted to NetCrypto per §1.4.

**FR-3 — Verification algorithm, controller authorization, and results.** Verification executes the full spec algorithm, including `@context` validation, `proofPurpose` matching, `domain`/`challenge` checking, and expiry. **Controller authorization (resolver path).** When verification runs through a resolver (FR-7), the algorithm additionally confirms that the proof's `verificationMethod` is *authorized* for the asserted `proofPurpose`: the resolved controller document must associate that method with the verification relationship corresponding to the purpose (`assertionMethod` proofs require the method under `assertionMethod`, `authentication` under `authentication`, ZCAP invocation/delegation under `capabilityInvocation`/`capabilityDelegation`), and the named controller must actually control the method. A method whose signature checks out but that is **not** listed under the required relationship fails verification — this is a distinct failure from a `proofPurpose` *field* mismatch, and the two are tested separately (AC-1). Verification returns a structured result (verified flag + problem details aligned with the processing-error codes defined by VC Data Integrity — `PROOF_VERIFICATION_ERROR`, `PROOF_TRANSFORMATION_ERROR`, `INVALID_DOMAIN_ERROR`, `INVALID_CHALLENGE_ERROR`, and `INVALID_VERIFICATION_METHOD` for the controller-authorization failure above) rather than throwing on invalid proofs; exceptions are reserved for malformed inputs and misconfiguration.

**FR-4 — Cryptosuite registry.** An open registry keyed by cryptosuite name. Each suite supplies its transformation, hashing, and proof-serialization implementations to the pipeline. Registering a 1.1-track revision or a deferred suite (`ecdsa-sd-2023`) must require no pipeline changes. Built-in registrations per package: `Core` registers the JCS suites; `Rdfc` registers the RDFC suites and `bbs-2023`. *Port reference:* zcap-dotnet's `ICryptoSuiteProvider`/`CryptoSuiteProvider` and `IDocumentCanonicalizer`/`DocumentCanonicalizerProvider` abstractions. **Legacy/type-named suites (verification).** The "no pipeline changes" contract also covers *verifying* pre–Data-Integrity Linked-Data-Signature proofs that name their algorithm by `type` (`Ed25519Signature2020`, `EcdsaSecp256r1Signature2019`, …) and carry **no** `cryptosuite` member. A suite declares the proof `type`(s) it verifies via `ICryptosuite.SupportedProofTypes` (a default interface member returning the single `DataIntegrityProof` type, so the 2022/2019 suites are unchanged and still dispatched by `cryptosuite` name). The registry maintains a secondary `type → suite` index for the *non-default* types only, and the verify pipeline dispatches by `cryptosuite` name first, falling back to proof `type` for legacy proofs — `cryptosuite`-named suites always win, the default type is never type-indexed, and each suite still re-validates `type`/`cryptosuite`/key/encoding/signature itself. The conformant `Core`/`Rdfc` suites still **create** only 2022/2019 proofs. Concrete legacy suites now ship in the opt-in **`DataProofsDotnet.Legacy`** package (issue #7): `Ed25519Signature2020` and `EcdsaSecp256r1Signature2019`, each with a JCS (default) and an RDFC variant, byte-identical to zcap-dotnet's 2020-era wire convention (the JCS path signs the document with the proof nested inside it; null object members are stripped to match zcap). They both **create and verify** (create dispatches via `GetByName` when proof options name the suite; verify dispatches by `type`), emit `type:"<suite>"` with no `cryptosuite` and a base58-btc `proofValue`, and are **not** in `CreateDefault()` (register explicitly). Documented, adversarially-reviewed limitations: the JCS variant cannot represent a W3C proof chain and **fails closed** on a document already carrying a `proof` member; the RDFC variant binds only `@context`-defined terms (inherent to JSON-LD/RDFC); and `EcdsaSecp256r1Signature2019` does not enforce low-`s` (ECDSA `proofValue`s are malleable — not unique identifiers).

**FR-5 — JCS suites.** Conformant `eddsa-jcs-2022` and `ecdsa-jcs-2019` (P-256 and P-384): proof-configuration canonicalization with JCS via NetCid, document canonicalization with JCS, `hashData = hash(canonicalProofConfig) ‖ hash(canonicalDocument)` with the hash function the suite mandates per curve, signing via NetCrypto, `proofValue` as base58-btc multibase. Verified against the W3C test vectors and interop-suite fixtures. **Porting caveat:** zcap-dotnet's JCS canonicalizer transfers, but its JCS *signing payload* uses the 2020-era embedded-proof convention (document signed with proof nested in it); `eddsa-jcs-2022`/`ecdsa-jcs-2019` require the separate-proof-config canonicalization + hash-concat that zcap currently applies only on its RDFC path — extend that mechanic to JCS here (§1.4).

**FR-6 — Proof sets and proof chains.** Adding a proof to a document that already carries proofs (set semantics); chains via `previousProof` with the spec's verify-time dependency checking.

**FR-7 — Verification-method resolver abstraction.** `IVerificationMethodResolver` defined in `Core`: resolves a verification-method URL to (a) public key material (`Multikey` canonical; JWK accepted via the `JsonWebKey` boundary exception), (b) the controller identifier, and (c) the set of verification relationships under which the controller document lists that method (`assertionMethod`, `authentication`, `capabilityInvocation`, `capabilityDelegation`, `keyAgreement`). Items (b) and (c) are the controller metadata FR-3's authorization check consumes — the resolver result must carry enough to decide whether the method is authorized for a given `proofPurpose`, not merely the raw key. All verify APIs come in two forms (concept D4): **raw-key overloads** (signature-only; no controller authorization, since no controller document is available) and **resolver overloads** (the full algorithm including controller authorization). `Core` ships no DID-aware implementation; a static/dictionary-backed resolver — carrying explicit per-method relationship sets so authorization (including its negative cases) can be exercised in tests and samples — is provided.

**FR-8 — Multikey and JWK key intake.** Helpers to accept verification material as `Multikey` (NetCid) or `JsonWebKey`, normalizing to the key representations NetCrypto providers consume. No other key envelope types appear in public APIs.

---

## 4. Functional requirements — Rdfc (RDF canonicalization family)

**FR-9 — JSON-LD processing and RDFC-1.0.** JSON-LD 1.1 expansion and RDF Dataset Canonicalization via dotNetRDF, wrapped behind this library's own canonicalizer interface; no dotNetRDF or Newtonsoft type appears in any public signature. Conformance is demonstrated by running the RDFC-1.0 test-suite fixtures in `Rdfc.Tests`, not assumed from the dependency.

**FR-10 — Document loader and external-retrieval posture.** A pluggable `IDocumentLoader` interface with a **decided default policy (owner-ruled, 2026-06-10): offline-only.** The default loader serves version-pinned, provenance-tracked copies of the core W3C contexts the v1 features require (VCDM 2.0 credentials context, the Data Integrity / cryptosuite / multikey contexts, the BBS context) embedded as assembly resources, and **fails closed** on any context outside the bundled set. A `CachingNetworkDocumentLoader` — ported from zcap-dotnet's proven `CachedContextLoader` — ships but is **never the default**: it must be explicitly constructed and registered. Rationale: verification is deterministic and performs no ambient network I/O, and a security operation's correctness never depends on a remote host being reachable. This same posture is the library-wide rule for **all** external retrieval — offline/local-cache by default, network strictly opt-in, behind a pluggable hook — including SD-JWT VC type-metadata retrieval (FR-17). Out of scope: context publication/hosting, and advanced caching strategy (TTL/eviction tuning, shared/distributed caches) beyond the shipped offline-default + opt-in loaders.

**FR-11 — RDFC suites.** Conformant `eddsa-rdfc-2022` and `ecdsa-rdfc-2019`: RDFC-1.0 canonicalization of document and proof configuration, per-suite hashing, NetCrypto signing, multibase `proofValue`. Verified against W3C test vectors and the `vc-di-eddsa`/`vc-di-ecdsa` interop-suite fixtures. *Porting source:* zcap-dotnet's `RdfcDocumentCanonicalizer` and its RDFC hash-concat in `ProofSigningPayloadBuilder` transfer directly (already conformant); update suite identifiers to the 2022/2019 generation and move into the `Rdfc` package per §1.4.

**FR-12 — `bbs-2023`.** The full base-proof / derived-proof lifecycle per the pinned Candidate Recommendation Draft (CRD snapshot 2026-04-07, re-pinned at PRD time): mandatory/selective JSON-pointer partitioning (RFC 6901), HMAC blank-node relabeling, base proof creation over NetCrypto `IBbsCryptoProvider` (parameterized ciphersuite per the NetCrypto decisions), derived-proof generation by the holder, derived-proof verification, and the CBOR-encoded multi-component `proofValue` structures (encoded with `System.Formats.Cbor`). Round-trip and fixture verification against the `vc-di-bbs` interop test suite. Behavior when BBS native binaries are absent follows NetCrypto's documented capability model: suite registration succeeds, use throws the documented exception.

---

## 5. Functional requirements — Jose (JOSE, SD-JWT)

**FR-13 — JWS.** Compact and JSON serialization (general and flattened), detached payload support, protected/unprotected headers, multi-signature in JSON serialization. Signature algorithms in v1: `EdDSA` (Ed25519, per RFC 8037), `ES256K` (secp256k1, per RFC 8812), `ES256`, `ES384` — all via NetCrypto `ISigner`/`ICryptoProvider`, mapping to NetCrypto `KeyType.Ed25519`/`Secp256k1`/`P256`/`P384`. **Signature-format gotcha (verified against NetCrypto source):** NetCrypto's default `ICryptoProvider.Sign` returns NIST-curve ECDSA in **DER** for back-compat; JOSE requires **IEEE P1363** (R‖S), so `ES256`/`ES384` MUST use the `EcdsaSignatureFormat.IeeeP1363` overload, while `Secp256k1` already returns 64-byte compact R‖S and `Ed25519` is already JOSE-native. `ES512` (ECDSA P-521 + SHA-512) is implemented and round-trip-tested in NetCrypto but is out of v1 scope (no stack consumer uses P-521 keys); RSA algorithms are likewise out of scope for v1 (no key in the stack is RSA). Porting source: `didcomm-dotnet` `JwsBuilder`/`JwsParser` (§1.4).

**FR-14 — JWE.** Compact and General JSON serialization, multi-recipient. Every JWE algorithm is **backed by a NetCrypto primitive; none is rolled locally.** Verified against NetCrypto's actual surface (`crypto-dotnet` `src/NetCrypto`, audited 2026-06-10): content encryption — `A256GCM` (`AesGcmCipher`), `A256CBC-HS512` (`AesCbcHmacCipher`), `XC20P` (`XChaCha20Poly1305Cipher`); key management — `A256KW` (`AesKeyWrap`), and the ECDH key-agreement variants assembled in `Jose` over NetCrypto's raw-ECDH-plus-KDF primitives (`ICryptoProvider.DeriveSharedSecret` returns the raw shared secret *Z* for X25519/P-256/P-384, and `ConcatKdf` derives the wrapping key — JOSE ECDH-ES/1PU use the NIST SP 800-56A Concat KDF (RFC 7518 §4.6), **not** HKDF, even though NetCrypto also exposes `Hkdf` for other uses). NetCrypto deliberately exposes *primitives*, not named JOSE algorithms, so `ECDH-ES+A256KW` and `ECDH-1PU+A256KW` (the latter pinned at `draft-madden-jose-ecdh-1pu-04`, required by the future didcomm adoption) are composed here — ECDH-1PU as Z = Ze‖Zs from two `DeriveSharedSecret` calls — with the APU/APV/Concat-KDF assembly ported from `didcomm-dotnet`, which already implements exactly this. (NetCrypto's ECDH covers X25519/P-256/P-384/P-521 — issue #61 *added* P-521, so curve availability is not a constraint; v1 JWE uses X25519/P-256/P-384, the curves the didcomm adoption needs, with P-521 left out of v1 scope by the FR-13 curve decision rather than by any gap.) The AC-3 checkpoint guards the standing invariant that no `Jose` algorithm bypasses NetCrypto.

**FR-15 — JWT and JWK.** JWT claims-set construction/validation (`exp`/`nbf`/`iat`/`iss`/`aud`/`sub` checks with configurable clock skew) atop FR-13. JWK handling: conversion to/from `Multikey` and NetCrypto key representations, JWK thumbprints (RFC 7638) using JCS-consistent member serialization, `kid` conventions.

**FR-16 — SD-JWT (RFC 9901).** Issuance: claim selection for selective disclosure, salted-hash disclosures, `_sd`/`_sd_alg`/`...` (array element) mechanics, decoy digests. Holder: disclosure selection and presentation assembly. Verification: digest validation and payload reconstruction. Key Binding JWT: issuance with `sd_hash`, audience/nonce binding, and verification per RFC 9901 §7.3.

**FR-17 — SD-JWT VC profile.** Per `draft-ietf-oauth-sd-jwt-vc-16` (re-pin verified 2026-06-10: -16 is the current latest, no -17 exists): media type, registered claims (`vct` et al.), issuer/holder/verifier validation and processing rules layered on FR-16. **Type-metadata (`vct`) retrieval follows the FR-10 posture:** resolution is offline/local-cache by default and never reaches the network unless the consumer opts in, exposed through a pluggable type-metadata resolver hook the consumer supplies (URL in the `vct` claim, a registry, or a local cache). Draft-sensitive logic is confined to profile types so a re-pin is localized.

**FR-18 — VC-JOSE-COSE (JOSE half).** The header parameters, content types, and processing rules for enveloping a VCDM 2.0 payload in a JWS per Securing VCs using JOSE & COSE. (COSE half: FR-19.)

---

## 6. Functional requirements — Cose

**FR-19 — COSE_Sign1, CWT, and VC-JOSE-COSE (COSE half).** `COSE_Sign1` signing/verification per RFC 9052 with the same v1 algorithm set as FR-13 (mapped to COSE algorithm identifiers); CWT claims per RFC 8392; the COSE half of VC-JOSE-COSE. All CBOR via `System.Formats.Cbor`; signing via NetCrypto.

---

## 7. Functional requirements — composition, examples, hygiene

**FR-20 — Developer examples (samples).** Standalone console projects under `samples/`, following the sibling-repo convention exactly: `DataProofsDotnet.Samples.<Topic>`, `OutputType=Exe`, `IsPackable=false`, project references into `src/`, banner-comment narration with step-by-step `Console.WriteLine` output, **no test frameworks**. The v1 set (one project per row; additions allowed, removals not):

| Sample | Demonstrates |
|---|---|
| `Samples.DataIntegrityJcs` | Sign + verify with `eddsa-jcs-2022` and `ecdsa-jcs-2019`; raw-key verification |
| `Samples.DataIntegrityRdfc` | `eddsa-rdfc-2022` / `ecdsa-rdfc-2019` with the offline document loader |
| `Samples.ProofSetsAndChains` | Proof sets; chains via `previousProof` |
| `Samples.BbsSelectiveDisclosure` | `bbs-2023` base proof → derived proof → verification, mandatory/selective pointers |
| `Samples.VerificationResolver` | Implementing `IVerificationMethodResolver`; resolver-driven full verification incl. proof purpose |
| `Samples.KeyStoreSigning` | Producing a Data Integrity proof, a JWS, an SD-JWT, and a COSE_Sign1 with a non-exporting `IKeyStore` signer |
| `Samples.Jws` | Compact + JSON serialization, EdDSA and ES256K, detached payload |
| `Samples.Jwe` | Multi-recipient JWE, ECDH-ES+A256KW and ECDH-1PU+A256KW, XC20P |
| `Samples.JwtAndJwk` | JWT claims validation; JWK ↔ Multikey conversion; thumbprints |
| `Samples.SdJwt` | Issuance with disclosures and decoys; holder presentation; KB-JWT |
| `Samples.SdJwtVc` | The SD-JWT VC profile end to end |
| `Samples.CoseCwt` | COSE_Sign1 + CWT round trip |
| `Samples.VcJoseCose` | Enveloping a VCDM 2.0 payload — JOSE and COSE halves |
| `Samples.DependencyInjection` | Composing the pipeline, suites, and resolvers via the DI package |

**FR-21 — Mechanical samples coverage (CI gate).** A `tasks/samples-coverage` tool, run in CI, that (a) enumerates the public API surface of all five packages, (b) statically analyzes the compiled samples for member references, and (c) **fails the build if any public type or member is not exercised by at least one sample.** Exclusions require an entry in a checked-in allowlist with a justification comment (e.g., trivially-generated equality members). 100% of the non-excluded public surface is covered. This is the FR-17 precedent from NetCrypto applied here.

**FR-22 — Dependency-injection package.** `AddDataProofs(...)` builder-style registration mirroring the `AddNetDid` idiom: registers the pipeline, the cryptosuite registry with per-package suite registration extensions (`AddJcsSuites()`, `AddRdfcSuites()`, `AddBbs2023()`, `AddJose()`, `AddCose()`), and accepts caller-supplied `IVerificationMethodResolver` registrations. The DI package composes; it does not hide the ability to construct everything manually (every sample except `Samples.DependencyInjection` constructs without DI).

**FR-23 — Exceptions and diagnostics.** A small exception hierarchy rooted at a library-base exception for malformed input/misconfiguration; verification failures are results, not exceptions (FR-3). No secrets, keys, or plaintext payloads in exception messages or logs. Logging via `Microsoft.Extensions.Logging.Abstractions` only, no mandatory logger.

**FR-24 — Public-API discipline.** Public-API surface tracking (analyzer-enforced shipped/unshipped API files) on all five packages from the first commit, so AC-7's surface review is mechanical.

---

## 8. Non-functional requirements

- **NFR-1** .NET 10; nullable enabled; implicit usings per sibling conventions; warnings as errors.
- **NFR-2** `System.Text.Json` exclusively in public behavior; Newtonsoft only as dotNetRDF's internal transitive inside `Rdfc`.
- **NFR-3** Async with `CancellationToken` for any operation that signs or resolves; synchronous verification paths permitted where no I/O occurs.
- **NFR-4** Thread safety: pipeline, registry, and suite instances are immutable/thread-safe after construction.
- **NFR-5** Deterministic outputs: given identical inputs, key material, and suite, byte-identical proofs/envelopes (modulo fields that are inherently random — salts, IVs, ephemeral keys — which MUST come from NetCrypto's randomness, never `System.Random`).
- **NFR-6** Constant-time comparisons for digest/MAC equality checks via `CryptographicOperations.FixedTimeEquals` — the single `System.Security.Cryptography` symbol allowlisted by the §2.2 / AC-6 BCL-crypto ban (it is a comparison utility, not a keyed or algorithmic primitive) — matching the porting source's existing practice.

---

## 9. Acceptance criteria (package-level; map to concept §10)

These criteria are written for autonomous execution by coding agents. Conventions that apply to all of them:

- **Binary outcomes only.** Every criterion is a named CI job that exits 0 or non-zero. No criterion depends on human judgment except where explicitly marked "review", and reviews are backed by a mechanical pre-check.
- **Fixtures are vendored, never fetched at test time.** All external test vectors and fixtures are copied into `tests/fixtures/<source>/` with a `PROVENANCE.md` per source directory recording: origin URL, git commit SHA or document version, retrieval date, and any local transformation applied. CI runs offline with respect to fixtures.
- **Pins are explicit.** Anything sourced from a draft or a moving repository records the exact draft number or commit SHA in `PROVENANCE.md`; the re-pin checkpoints (§12) update these files in a reviewable diff.
- **One job per criterion**, named `ac-1` … `ac-11` in `.github/workflows/ci.yml`, all required for merge to main and for `publish.yml` (AC-11 gates publish specifically).

---

**AC-1 — Cryptosuite conformance.**
*Fixtures:*
- Test vectors from the governing specs, vendored to `tests/fixtures/w3c/vc-di-eddsa/`, `.../vc-di-ecdsa/`, `.../vc-di-bbs/`: the worked test-vector appendices of DI EdDSA Cryptosuites 1.0 (REC), DI ECDSA Cryptosuites 1.0 (REC), and DI BBS Cryptosuites (CRD pinned per §12.3) — including input documents, key material, proof options, and expected proofs.
- Interop fixtures harvested from the W3C test-suite repositories (`w3c/vc-di-eddsa-test-suite`, `w3c/vc-di-ecdsa-test-suite`, `w3c/vc-di-bbs-test-suite`), pinned by commit SHA.
*Procedure (xunit theories in `Core.Tests` and `Rdfc.Tests`):*
1. *Verification direction (all suites):* every spec-provided and interop-provided signed document verifies successfully through the FR-2/FR-3 pipeline with the fixture's key material via a static resolver; every fixture's documented negative case (tampered document, wrong key, `proofPurpose`-field mismatch) returns `verified=false` with the expected problem-detail code — never an unhandled exception.
2. *Creation direction, deterministic suites (`eddsa-jcs-2022`, `eddsa-rdfc-2022` — Ed25519 signing is deterministic):* re-create the proof from the fixture's inputs and assert **byte-identical** `proofValue` against the expected vector.
3. *Creation direction, randomized suites (ECDSA suites, `bbs-2023`):* create a proof from fixture inputs, then verify it through the pipeline (round-trip), and additionally assert intermediate determinism where the spec defines it — canonical form bytes and `hashData` MUST be byte-identical to the vector even when the final signature is randomized.
4. *`bbs-2023` lifecycle:* from a fixture base proof, derive proofs for each fixture-defined selective-disclosure pointer set and verify them; derive from our own base proof and verify; assert mandatory-pointer violations are rejected.
5. *Controller authorization (FR-3, resolver path) — constructed fixtures:* the W3C vectors do not exercise authorization failures, so a small provenance-tracked fixture set under `tests/fixtures/constructed/controller/` carries controller documents with known relationship sets. Assert: (a) a proof whose `verificationMethod` is listed under the relationship matching its `proofPurpose` verifies; (b) a proof whose signature is valid but whose method is **not** listed under the required relationship fails with `INVALID_VERIFICATION_METHOD` — and this case is asserted to be distinct from the `proofPurpose`-field mismatch of step 1 (same key, valid signature, differing only in controller authorization); (c) a `verificationMethod` whose controller does not control it fails; (d) the matching raw-key overload (no resolver) verifies the same signature, confirming the authorization gate lives only on the resolver path.
6. *Proof sets and chains (FR-6) — constructed fixtures:* under `tests/fixtures/constructed/sets-chains/`. Assert: (a) a document carrying a **proof set** (two independent proofs) verifies, and tampering with either proof fails only that proof; (b) a **proof chain** via `previousProof` verifies when the dependency order holds; (c) a chain whose `previousProof` reference is missing or out of order fails with the expected problem code; (d) adding a proof to an already-proofed document produces spec-correct set/chain structure (byte-checked against the constructed expected output for the deterministic suites).
*Pass:* job `ac-1` green = all theories pass; any skipped theory fails the job (skips are not permitted in conformance suites).

**AC-2 — RDFC-1.0 canonicalizer conformance.**
*Fixtures:* the W3C RDF Dataset Canonicalization test suite (`w3c/rdf-canon` repository, `tests/` manifest), pinned by commit SHA, vendored to `tests/fixtures/w3c/rdf-canon/`.
*Procedure:* a manifest-driven xunit theory in `Rdfc.Tests` feeds each test-case input through the `Rdfc` public canonicalizer interface (not raw dotNetRDF — the wrapper is the unit under test) and byte-compares output against the expected canonical form; manifest entries typed as negative/error cases must produce the wrapper's documented exception.
*Pass:* job `ac-2` green = every manifest entry passes; the job also asserts the manifest entry count matches the count recorded in `PROVENANCE.md` (guards against silently dropped cases).

**AC-3 — JOSE / SD-JWT / SD-JWT VC / VC-JOSE-COSE (JOSE half) conformance and oracle cross-verification.**
*Fixtures:* RFC 7520 (JOSE cookbook) examples vendored to `tests/fixtures/ietf/rfc7520/`; RFC 8037 EdDSA appendix vectors to `.../rfc8037/`; RFC 7638 JWK thumbprint worked examples to `.../rfc7638/`; RFC 7518 Appendix C ECDH-ES Concat-KDF example to `.../rfc7518/`; the ECDH-1PU example from `draft-madden-jose-ecdh-1pu-04` to `.../ecdh-1pu-04/`; RFC 9901 SD-JWT worked examples (disclosures, presentations, KB-JWT) to `.../rfc9901/`; SD-JWT VC examples from `draft-ietf-oauth-sd-jwt-vc-16` to `.../sd-jwt-vc-16/`. **ES256K** is implemented per RFC 8812; neither RFC 8812 nor the JOSE oracle carries a worked ES256K JWS vector (`jose-jwt`'s closed `JwsAlgorithm` enum excludes ES256K), so its coverage is a generated vector set whose signatures are cross-verified **at generation time against an independent secp256k1 ECDSA implementation over the exact JWS signing input**, frozen as regression vectors under `tests/fixtures/generated/`. **XC20P** likewise has no oracle (not in `jose-jwt`); same generated-and-frozen treatment. Both generated sets check in their generation script and a `PROVENANCE.md`.
*Procedure:*
1. *Vector theories:* consume/produce each fixture through `Jose` public APIs; byte-compare where the operation is deterministic, verify-direction otherwise.
2. *JWK thumbprints (FR-15):* compute RFC 7638 thumbprints for the RFC 7638 example keys and assert byte-equality with the expected thumbprints; assert thumbprint stability across `Multikey`↔JWK round-trips.
3. *Oracle cross-verification (test project only; `jose-jwt` and `Owf.Sd.Jwt`/SdJwt.Net are `PackageReference`s of `Jose.Tests` exclusively).* The set under test is the **full computed intersection** of {algorithms this library implements} ∩ {algorithms the oracle's published surface supports} — enumerated programmatically from the oracle's algorithm registry, not hard-coded — and the theory **fails if any algorithm this library implements that the oracle also supports is left uncovered**. With `jose-jwt` that intersection is currently at least `ES256`, `ES384`, `A256GCM`, `A256CBC-HS512`, `A256KW`, and `ECDH-ES+A256KW`; `EdDSA`, `ES256K`, `XC20P`, and `ECDH-1PU+A256KW` are outside it (not in `jose-jwt`) and are therefore covered by the RFC/generated vectors of step 1 instead. For each algorithm in the intersection: (a) a JWS/JWE produced by `DataProofsDotnet.Jose` verifies/decrypts in `jose-jwt`; (b) one produced by `jose-jwt` verifies/decrypts here. For SD-JWT: presentations produced here verify in SdJwt.Net and vice versa, including KB-JWT validation, over the algorithm both support.
4. *FR-14 ↔ NetCrypto equivalence checkpoint:* assert the set of JWE content-encryption and key-management algorithms `Jose` actually registers equals the set derivable from NetCrypto v1's published primitive surface — no implemented algorithm lacks a NetCrypto backing, and no NetCrypto-backable standard JOSE algorithm is missing without a corresponding entry in a checked-in `jwe-algorithm-omissions.md` with a reason. Fails on any unexplained divergence.
5. *SD-JWT VC profile rules (FR-17) — beyond generic SD-JWT:* assert the profile-specific behavior, not just SD-JWT mechanics — `vct` presence and validation, the SD-JWT VC media type (`dc+sd-jwt`, with the transitional `vc+sd-jwt` accepted on input), the registered-claim handling, and the issuer/holder/verifier processing rules; assert a credential missing `vct` or carrying a disallowed claim shape is rejected with the documented failure. Type-metadata retrieval is exercised against a local-cache resolver (FR-17 posture), never the network.
6. *VC-JOSE-COSE, JOSE half (FR-18):* envelope a VCDM 2.0 payload as a JWS and assert the spec's content type (`application/vc+jwt`) and required header parameters are produced and validated on the round trip; assert a wrong/absent content type is rejected. (COSE half: AC-4.)
7. *Negative-path theories:* per RFC 9901 security considerations — rejected `none`/unexpected `alg`, tampered disclosure, digest mismatch, KB-JWT `sd_hash` mismatch, expired/replayed nonce — each returns the documented failure, never an unhandled exception.
*Pass:* job `ac-3` green = all of the above; the job additionally greps `src/**/*.csproj` and fails if `jose-jwt` or SdJwt.Net appears outside `tests/`.

**AC-4 — COSE/CWT and VC-JOSE-COSE (COSE half) conformance.**
*Fixtures:* `COSE_Sign1` examples from the COSE WG examples repository (`cose-wg/Examples`, pinned commit) filtered to the v1 algorithm set, vendored to `tests/fixtures/cose-wg/`; CWT examples from RFC 8392 Appendix A to `.../rfc8392/`.
*Procedure:* verify-direction theories for all fixtures through `Cose` public APIs; creation round-trips for each v1 algorithm; CWT claims validation against the Appendix A claim sets including expiry handling. *VC-JOSE-COSE, COSE half (FR-19):* envelope a VCDM 2.0 payload as a `COSE_Sign1` and assert the spec's content type (`application/vc+cose`) and required COSE header parameters are produced and validated on the round trip; assert a wrong/absent content type is rejected.
*Pass:* job `ac-4` green.

**AC-5 — didcomm JWS/JWE behavior parity.**
*Setup contract (Phase B):* the porting agent copies the JWS/JWE test files from `didcomm-dotnet` at a recorded commit SHA into `tests/DataProofsDotnet.Jose.Tests/Parity/`, and writes `tests/.../Parity/PARITY.md` mapping every ported test file to its source path and SHA.
*Allowed modifications, exhaustively:* namespace/using statements, type and member renames required by the new public API, test-framework attribute namespaces. **Assertion content (expected values, asserted properties, fixture bytes) MUST NOT change.**
*Mechanical check:* a `tasks/parity-diff` tool that, for each `PARITY.md` pair, extracts assertion statements (lines containing the test framework's assertion invocations) from both files, normalizes identifiers per the recorded rename map, and fails on any difference in literals or asserted structure.
*Pass:* job `ac-5` green = parity suite passes **and** `parity-diff` reports zero assertion differences.

**AC-6 — Dependency hygiene and NetCrypto-only crypto.**
*Procedure:* a `tasks/dependency-hygiene` tool run in CI:
1. Executes `dotnet list <project> package --include-transitive --format json` for every project under `src/`.
2. Asserts the §2.2 matrix exactly: fails if dotNetRDF or Newtonsoft.Json appears in any closure except `DataProofsDotnet.Rdfc`; fails if any of `NetDid.*`, `jose-jwt`, SdJwt.Net/`Owf.Sd.Jwt`, `NSec.*`, `NBitcoin.*`, `Nethermind.*` appears in any `src/` closure at all.
3. Repeats the check against the *packed* `.nupkg` dependency groups (what consumers actually inherit), not just project graphs.
4. **Banned-symbol scan (NetCrypto-only crypto, hashing included).** A Roslyn-based check (or `BannedApiAnalyzers` with a checked-in `BannedSymbols.txt`) over all `src/` compilations fails on any reference to a `System.Security.Cryptography` cryptographic primitive — hash algorithms (`SHA256`/`SHA384`/`SHA512`/`SHA3_*`, `IncrementalHash`, `HMAC*`), signature algorithms (`ECDsa`/`RSA`/`DSA` and their platform subclasses), and AEADs (`AesGcm`/`AesCcm`/`ChaCha20Poly1305`). The **only** allowlisted symbol from that namespace is `CryptographicOperations.FixedTimeEquals` (NFR-6). This is what catches direct BCL hashing that a package-dependency check cannot see; every such operation must instead route through NetCrypto's hashing/signing/AEAD API.
*Pass:* job `ac-6` green = zero violations across project graphs, package graphs, and the banned-symbol scan.

**AC-7 — Public-API surface discipline.**
*Procedure:*
1. `Microsoft.CodeAnalysis.PublicApiAnalyzers` enabled on all five packages from the first commit (FR-24); CI builds with warnings-as-errors so any undeclared public API fails the build.
2. A `tasks/api-surface-scan` step parses the `PublicAPI.Shipped.txt`/`PublicAPI.Unshipped.txt` files and enforces the concept's "no backend type" posture as a **positive allowlist**, not a finite blocklist: every type appearing in a public signature must belong to one of (i) this library's own namespaces (`DataProofsDotnet.*`); (ii) a **specific, enumerated** subset of the BCL — *not* all of `System.*` — namely the scalar/primitive and span types (`System.Byte`, `System.String`, `System.Boolean`, the integer types, `System.ReadOnlySpan<>`/`ReadOnlyMemory<>`/`Span<>`/`Memory<>`), `System.Text.Json.*` (the sanctioned serialization surface), the async types (`System.Threading.Tasks.Task`/`ValueTask`, `System.Threading.CancellationToken`), the common collection interfaces (`System.Collections.Generic.*`), and the date/URI scalars the models need (`System.DateTimeOffset`, `System.TimeSpan`, `System.Uri`, `System.Guid`) — maintained in a checked-in `tasks/api-surface-scan/bcl-allowlist.txt`, additions requiring justification. This deliberately **excludes** backend/encoding BCL namespaces — above all `System.Formats.Cbor.*` (CBOR is an internal encoding detail of `Cose`; no `CborReader`/`CborWriter` may surface in a public signature), and likewise `System.Security.Cryptography.*`, `System.Xml.*`, `System.Net.*`, and `System.IO.*`. The remaining permitted origins are (iii) `Microsoft.Extensions.*` abstractions (the DI package only); (iv) NetCrypto's and NetCid's public namespaces; and (v) the **single** type `Microsoft.IdentityModel.Tokens.JsonWebKey`. Anything else fails — and because the rule is an allowlist, this explicitly catches any *other* `Microsoft.IdentityModel.Tokens.*` or `Microsoft.IdentityModel.*` type (only `JsonWebKey` is permitted, not the namespace), as well as any `VDS.RDF.*`, `Newtonsoft.*`, `Jose.*`, `SdJwt.*`, `NSec.*`, `NBitcoin.*`, or `Nethermind.*` type, without needing to enumerate them.
3. Human review of the API files at each phase exit is advisory; the mechanical scan is the gate.
*Pass:* job `ac-7` green = analyzer clean + scan clean.

**AC-8 — No-key-surrender property.**
*Basis (verified against NetCrypto source):* NetCrypto's `IKeyStore` exposes **no key-export method** — its only key-using operations are `SignAsync(alias, …)` and `CreateSignerAsync(alias)`, and `ISigner` surfaces only the public key and `SignAsync`. So no-key-surrender is structural at the abstraction, not an opt-in: there is nothing to export. This AC proves `DataProofsDotnet` actually *uses* that path for every signature-bearing artifact rather than reaching for raw private bytes anywhere.
*Procedure:* `Core.Tests` defines `RecordingKeyStore : IKeyStore`, wrapping NetCrypto's `InMemoryKeyStore`, that records which members are invoked. After setup (`GenerateAsync`/`ImportAsync` only), a test suite (mirrored by `Samples.KeyStoreSigning`) produces — via a `KeyStoreSigner`/`ISigner` backed by that store — one Data Integrity proof per shipped suite (BBS included where native binaries are present), a compact JWS, a multi-recipient JWE (sender-authenticated path), an SD-JWT with KB-JWT, and a COSE_Sign1, then verifies each artifact. The job asserts that during artifact production **only** `SignAsync`/`CreateSignerAsync`/`GetInfoAsync` were touched — no other member, and (trivially, since the interface has none) no export path. A companion API-surface assertion confirms every public signing entry point in `DataProofsDotnet` accepts an `ISigner` or an `IKeyStore`, never raw private-key bytes.
*Pass:* job `ac-8` green = all artifacts produced and verified, with signing access confined to the signing-only members.

**AC-9 — Samples coverage gate (FR-21).**
*Procedure:* `tasks/samples-coverage` runs after `dotnet build`:
1. Enumerates the public API of the five built `src/` assemblies via `System.Reflection.Metadata` (public types, methods, properties, constructors; compiler-generated members excluded by attribute).
2. Reads the member references (MemberRef/MethodDef tokens) of every built `samples/` assembly.
3. Subtracts the allowlist at `tasks/samples-coverage/allowlist.txt` — one fully-qualified member per line, each line followed by a `# justification:` comment; lines without justification fail the tool.
4. Fails if any remaining public member is referenced by zero samples; emits `samples-coverage-report.md` as a CI artifact listing per-member → sample mapping.
*Pass:* job `ac-9` green = 100% of non-allowlisted public API referenced by ≥1 sample, and every sample project itself runs to exit code 0 in the same job.

**AC-10 — Pack, install, and smoke.**
*Procedure:* in `publish.yml` (and on main in `ci.yml`):
1. `dotnet pack` all five packages into a local folder feed.
2. For each package: `dotnet new console` in a clean temp directory, `dotnet add package <id>` against the local feed (plus the package's documented prerequisites only), build, and run a checked-in per-package smoke `Program.cs` from `tasks/smoke/` (JCS proof round-trip for `Core`; JWS round-trip for `Jose`; COSE_Sign1 round-trip for `Cose`; RDFC canonicalization of a bundled document for `Rdfc`; `AddDataProofs` resolution for the DI package).
3. Assert each smoke program exits 0 and prints its terminal `OK` line.
*Pass:* job `ac-10` green = five clean-room installs, five exit-0 smoke runs.

**AC-11 — Package identity & publish readiness (publish gate).**
*Procedure:* a `tasks/package-identity` step, run in `publish.yml` before the push:
1. For each of the five `DataProofsDotnet.*` IDs, query the nuget.org registration endpoint (`https://api.nuget.org/v3/registration5-semver1/{id-lowercase}/index.json`): a 404 means the ID is unregistered and claimable; a 200 means it already exists and the job asserts it is owned by this account (the push credentials' owner) — any 200 for an ID owned by someone else fails the gate.
2. Assert the **`DataProofsDotnet` ID prefix is reserved** to the owner (NuGet ID prefix reservation), so the family cannot be squatted between releases; if the reservation is not yet in place, the gate fails with a pointer to the one-time owner action (request prefix reservation via the NuGet account), since prefix reservation is an owner step, not an automatable one.
3. Assert each package's `PackageId` matches its project's intended ID exactly (guards against a typo shipping under a squattable name).
*Pass:* job `ac-11` green = all five IDs claimable-or-owned, prefix reserved, IDs exact. **Publishing is blocked on `ac-1`–`ac-11` all green;** AC-11 is the gate that makes "published" in the Definition of Done (§1.3) safe rather than a race.

---

## 10. Phases

- **Phase A — Core.** Repo scaffold (conventions copied from siblings), FR-1–FR-8: models, pipeline, registry, JCS suites, resolver abstraction. Exit: AC-1 green for the JCS suites **plus the controller-authorization (FR-3/FR-7) and proof-set/chain (FR-6) steps**.
- **Phase B — Jose foundation.** FR-13–FR-15: didcomm JWS/JWE port + parity suite, JWT/JWK. Exit: AC-3 green for the JWS/JWE and JWK-thumbprint portions **and the FR-14 ↔ NetCrypto primitive-backing checkpoint** (NetCrypto's surface is already verified — FR-14; the check is the standing CI guard that no `Jose` algorithm bypasses it), AC-5 green.
- **Phase C — Selective disclosure (JSON).** FR-16–FR-17: SD-JWT, KB-JWT, SD-JWT VC. Exit: AC-3 green for the SD-JWT **and SD-JWT VC profile** portions.
- **Phase D — CBOR side and binding.** FR-19, FR-18: COSE_Sign1, CWT, VC-JOSE-COSE both halves. Exit: AC-4 green (incl. the VC-JOSE-COSE COSE half) **and** the AC-3 VC-JOSE-COSE JOSE-half step green.
- **Phase E — Rdfc.** FR-9–FR-11 first (loader, canonicalizer, RDFC suites), then FR-12 (`bbs-2023`) last — the long pole rides on a proven pipeline. Exit: AC-1 (full), AC-2 green.
- **Phase F — Composition and gates.** FR-22 (DI), FR-20/FR-21 (samples + coverage tool), FR-23/FR-24 finalization, AC-6–AC-11 (including the AC-11 package-identity publish gate), packaging and publish.

---

## 11. Out of scope (v1)

`ecdsa-sd-2023` (deferred, D3; pre-assigned to `Rdfc`); RSA JOSE algorithms; any cryptographic primitive implementation; DID resolution or any `net-did` reference; credential data-model validation, status lists, presentation exchange; ZCAP/DIDComm protocol semantics; any change to sibling repositories; network-default JSON-LD loading (FR-10); JSON-LD context authoring/hosting.

---

## 12. Resolved decisions and phase-time checkpoints

Every item the concept delegated to the PRD is settled here; nothing remains pending owner input. Two forward-looking checkpoints remain, and they are genuinely phase-time — re-verifying a frozen draft and diffing it against what was built — not deferred decisions.

1. **Document-loader / external-retrieval posture — RESOLVED (owner-ruled, 2026-06-10).** Offline-only default with embedded, provenance-tracked core contexts and fail-closed behavior; opt-in `CachingNetworkDocumentLoader`; the same posture governs SD-JWT VC `vct` type-metadata retrieval, behind a pluggable hook. Specified in FR-10 and FR-17.
2. **SD-JWT VC pin — SET (2026-06-10).** Pinned to `draft-ietf-oauth-sd-jwt-vc-16`; re-pin verified against the datatracker the same day — -16 is the current latest, no -17 exists. *Phase-C checkpoint:* re-verify the latest draft at Phase C start, diff for normative changes against the implemented profile, and update the relevant `PROVENANCE.md` in a reviewable diff if it has moved.
3. **`bbs-2023` pin — SET (2026-06-10).** Pinned to the `vc-di-bbs` Candidate Recommendation Draft snapshot dated 2026-04-07; confirmed still a CRD (not advanced to CR/REC). *Phase-E checkpoint:* re-verify the latest CRD/CR at Phase E start, diff for normative changes against the implemented suite, and update `PROVENANCE.md` accordingly.
