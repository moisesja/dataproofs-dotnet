# DataProofsDotnet — Concept Document

**Repository:** `dataproofs-dotnet` · **Root namespace / PackageId family:** `DataProofsDotnet` · **Status:** Concept (pre-PRD) · **Date:** 2026-06-10

---

## 1. Purpose and positioning

`DataProofsDotnet` secures a document with a proof. It is the single home for both proof families defined by the W3C and IETF securing-mechanism landscape:

- **Embedded proofs** — W3C Data Integrity: a `proof` block carried inside a JSON-LD document, produced by the transform → canonicalize → hash → sign → encode pipeline, including proof sets and proof chains.
- **Enveloping proofs** — JOSE, COSE, and SD-JWT: the document is wrapped in a signed and/or encrypted container (JWS, JWE, COSE_Sign1, SD-JWT), including the VC-JOSE-COSE binding for carrying VCDM 2.0 payloads.

### 1.1 Why one library

Embedded and enveloping proofs are two halves of one concern — securing data — over a shared cryptographic and encoding foundation. Downstream libraries need both: `credentials-dotnet` issues and verifies credentials in Data Integrity, VC-JOSE-COSE, and SD-JWT VC forms; `zcap-dotnet` secures capabilities with Data Integrity; `didcomm-dotnet` builds its envelopes on JWS/JWE. Splitting the families into separate libraries would force every consumer except `didcomm-dotnet` to take both anyway, while duplicating the shared plumbing (key handling, base64url/multibase encoding, canonicalization access, verification-method resolution).

### 1.2 Position in the dependency stack

`DataProofsDotnet` sits in the identity-and-proofs layer. It depends **only** on:

- **`crypto-dotnet` (NetCrypto)** — every cryptographic operation: signing and verification through `ISigner`/`ICryptoProvider`, BBS through `IBbsCryptoProvider`, AEADs and key wrap for JWE, hashing.
- **`net-cid` (NetCid)** — multibase, multicodec, multihash, `Multikey`, and the RFC 8785 JCS canonicalizer.

It is consumed by `credentials-dotnet`, `zcap-dotnet`, and `didcomm-dotnet`. It never references `net-did`: DID resolution enters only through the resolver abstraction defined in §3.6.

### 1.3 Reference implementations (seeds and oracles)

Grounded by code audit of the sibling repositories on 2026-06-10:

| Source | Role | Notes |
|---|---|---|
| `zcap-dotnet` `ZcapLd.Core/Cryptography` + `Models` | **Porting source — embedded proofs** | Confirmed by audit (2026-06-10) to contain a substantially conformant Data Integrity implementation: a cryptosuite provider, JCS + RDFC canonicalizers behind `IDocumentCanonicalizer`, a `ProofSigningPayloadBuilder` doing the spec-correct `SHA-256(proofConfig) ‖ SHA-256(document)` hash-concat (RDFC path), `Proof`/`ProofSet` models, a `SignatureVerifier`, and a `CachedContextLoader`. The conformant embedded-proof engine the stack needs already exists here — this is the Data Integrity counterpart to didcomm's JOSE code. Ported with adaptations: generalize from ZCAP `Capability`/`Invocation` to arbitrary documents; update 2020-era suite identifiers to the `DataIntegrityProof` + `cryptosuite` 2022/2019 generation (incl. extending the hash-concat to the JCS suites — zcap's JCS path uses the older embedded convention); reroute raw-private-key signing to NetCrypto `ISigner`; split the RDFC canonicalizer into the `Rdfc` package. Copying code/tests *from* this repo is in scope; modifying it is not. |
| `didcomm-dotnet` `src/DidComm.Core/Jose/` | **Porting source — enveloping proofs** | ~1,100 lines of proven JWS/JWE building and parsing (builders, parsers, protected headers, APU/APV computation, recipient key wrap) over NSec-backed primitives now shipping in NetCrypto, plus `Jwk`/`JwkConversion`/`Base64Url`. Port, don't reinvent; algorithms and envelopes are unchanged, so a true behavior-parity port. Its `ISecretsResolver`-in-core + `Adapters.NetDid`-implementation pattern is the precedent for the verification-method resolver (§3.6). Copying code and tests *from* this repo is in scope; modifying it is not. |
| `net-did` (`NetDid.Core/Crypto/DataIntegrity` + DID-method parsing) | **Source — proof-record model & verification-method resolution** | Two genuinely reusable assets, leveraged per the dependency rules. **(1) Proof-record model — copy-in-scope:** net-did carries the modern `DataIntegrityProof` shape (`type: DataIntegrityProof` + named `cryptosuite`), which zcap's 2020-era `Ed25519Signature2020` models predate; it is reconciled into `Core`'s proof model (FR-1). **(2) Verification-method resolution — leveraged downstream, not copied here:** net-did's `did:key`/`did:peer`/`did:webvh` parsing is substantial, tested resolution work, leveraged as the concrete implementation behind the `IVerificationMethodResolver` that net-did supplies at the composition layer (§8). It is *not* copied into `Core`, because the dependency rules forbid this library hard-coding `did:key` or referencing `net-did` — leveraging it at net-did's own layer is how the stack reuses it without inverting the dependency arrow. net-did's `eddsa-jcs-2022` engine is the identifier/encoding reference for that suite; because its signing step omits proof-configuration hashing, the conformant `SHA-256(proofConfig) ‖ SHA-256(document)` hash-concat is taken from the zcap port rather than from net-did. Modifying `net-did` is out of scope; its did:webvh conformance question stays in that repository's backlog. |
| `jose-jwt` (dvsekhvalnov) | **Dev-time interop oracle only** | Rejected as a dependency (decision 1): its `JwsAlgorithm` is a closed enum with no EdDSA and no ES256K members; keys must be handed over as framework objects (incompatible with `IKeyStore`-held keys); Newtonsoft.Json serialization; newest TFM net6.0. Its test vectors remain valuable for the algorithms that overlap (ES256/ES384, RSA suites, AES-GCM JWE). |
| `Owf.Sd.Jwt` (SdJwt.Net) | **Dev-time interop oracle only** | Rejected as a dependency (decision 1): issuer/verifier signing flows through `Microsoft.IdentityModel` `SigningCredentials`, which has no native EdDSA; adapting it means writing the signing layer anyway. Its disclosure and KB-JWT vectors serve as cross-checks. |
| W3C interop test suites (`vc-di-ecdsa-test-suite`, `vc-di-bbs-test-suite`) and RFC test vectors | **Conformance fixtures** | Primary acceptance evidence for the cryptosuites and envelope formats (§10); the conformance pin for the ported zcap pipeline, since suite identifiers change on port. |

Test oracles are dev-dependencies of the test project only. No runtime package of `DataProofsDotnet` references them.

---

## 2. Specifications

Statuses verified 2026-06-10.

| Specification | Version targeted | Status | Notes |
|---|---|---|---|
| VC Data Integrity | 1.0 | W3C Recommendation (2025-05-15) | A 1.1 Working Draft track exists (with VCDM 2.1); v1 targets 1.0 and tracks 1.1. |
| DI EdDSA Cryptosuites (`eddsa-rdfc-2022`, `eddsa-jcs-2022`) | 1.0 | W3C Recommendation | 1.1 WD published 2026-04-16; tracked, not targeted. |
| DI ECDSA Cryptosuites (`ecdsa-rdfc-2019`, `ecdsa-jcs-2019`) | 1.0 | W3C Recommendation | 1.1 WD published 2026-04-16; tracked, not targeted. `ecdsa-sd-2023` deferred (decision 3). |
| DI BBS Cryptosuites (`bbs-2023`) | 1.0 | W3C Candidate Recommendation Draft (CRD, 7 April 2026) | Pre-final; re-pinned 2026-06-10 to the 2026-04-07 CRD snapshot (confirmed still a CRD, not advanced to CR/REC). Churn risk accepted (decision 2), managed as in NetCrypto; Phase-E re-verify checkpoint. |
| Securing VCs using JOSE & COSE (VC-JOSE-COSE) | 1.0 | W3C Recommendation (2025-05-15) | Both JOSE and COSE halves in v1. |
| RDF Dataset Canonicalization (RDFC-1.0) | 1.0 | W3C Recommendation (2024-05-21) | Via dotNetRDF, isolated in the `Rdfc` package (§5). |
| JSON-LD | 1.1 | W3C Recommendation | Processing (expansion/compaction) via dotNetRDF, isolated in `Rdfc`. |
| JCS | RFC 8785 | IETF RFC (final) | Provided by `net-cid`; not reimplemented here. |
| JOSE — JWS/JWE/JWK/JWA/JWT | RFC 7515–7519 | IETF RFC (final) | |
| COSE | RFC 9052 | IETF RFC (final) | `COSE_Sign1` in v1. |
| CWT | RFC 8392 | IETF RFC (final) | |
| SD-JWT | RFC 9901 | IETF RFC (final) | Including Key Binding JWT. |
| SD-JWT VC | `draft-ietf-oauth-sd-jwt-vc-16` | IETF Internet-Draft (2026-04-24) | Pre-final ("Verifiable Digital Credentials" retitle, references RFC 9901). Pinned at -16; re-pin verified 2026-06-10 (-16 is still the latest); Phase-C re-verify checkpoint. |

---

## 3. Functional scope (v1)

Per decision 2, v1 ships the full surface below (option A): both families, both encodings, all canonicalization paths — minus only `ecdsa-sd-2023` (decision 3).

### 3.1 Embedded proofs — Data Integrity

- The general proof pipeline per VC Data Integrity 1.0: transformation, canonicalization, hashing, proof serialization, `proofValue` encoding; full verification algorithm including `@context` validation and proof-purpose checking.
- Proof sets and proof chains (`previousProof`).
- Cryptosuite registry with five suites in v1:
  - `eddsa-jcs-2022`, `ecdsa-jcs-2019` — JCS canonicalization via `net-cid`.
  - `eddsa-rdfc-2022`, `ecdsa-rdfc-2019` — RDFC-1.0 canonicalization.
  - `bbs-2023` — selective disclosure with unlinkable derived proofs: base proof / derived proof split, mandatory and selective JSON pointers (RFC 6901), HMAC blank-node relabeling, CBOR-encoded multi-component `proofValue`, over NetCrypto's `IBbsCryptoProvider` with the parameterized ciphersuite established in the NetCrypto decisions.
- The registry is open: suites register against a common abstraction so deferred suites (`ecdsa-sd-2023`) and future 1.1-track revisions slot in without pipeline changes.

### 3.2 Canonicalization

- **JCS (RFC 8785):** consumed from `net-cid`. Not reimplemented.
- **RDFC-1.0 + JSON-LD 1.1:** via dotNetRDF, confined to the `Rdfc` package. dotNetRDF and any transitive Newtonsoft.Json never appear on any other package's dependency closure.

### 3.3 Enveloping proofs — JSON side (JOSE, SD-JWT)

- JWS (compact and JSON serialization), JWE (compact and General JSON serialization, multi-recipient), JWT claims handling, JWK representation and thumbprints.
- Algorithm surface driven by stack needs: EdDSA (Ed25519) and ES256K (secp256k1) are first-class — the two algorithms the rejected third-party libraries cannot provide — alongside ES256/ES384; JWE content encryption and key management per the algorithms NetCrypto v1 ships (A256GCM, A256CBC-HS512, A256KW, XC20P, ECDH-ES variants with Concat-KDF).
- All signing and encryption route through NetCrypto abstractions; private keys held in an `IKeyStore` never need to be exportable.
- SD-JWT (RFC 9901): salted-hash disclosures, `_sd`/`_sd_alg` mechanics, decoy digests, holder presentation, Key Binding JWT issuance and verification.
- SD-JWT VC profile (`draft -16`): media type, registered claims, validation and processing rules for issuer, holder, and verifier roles.

### 3.4 Enveloping proofs — CBOR side (COSE, CWT)

- `COSE_Sign1` signing and verification (RFC 9052) and CWT claims (RFC 8392).
- CBOR encoding via the BCL `System.Formats.Cbor` — no third-party dependency. CBOR was deliberately excluded from `crypto-dotnet`; `DataProofsDotnet` owns it, and the same encoder serves the `bbs-2023` `proofValue` structures.

### 3.5 VC-JOSE-COSE binding

- The header parameters, content types (`application/vc+jwt`, `application/vc+cose`, related media types), and processing rules for carrying a VCDM 2.0 payload inside a JOSE or COSE envelope — both halves in v1.

### 3.6 Verification model (decision 4)

Dual surface:

- **Raw-key primitives:** every verify operation is available taking explicit public key material — `Multikey` (from `net-cid`) as the canonical representation, JWK accepted via the `Microsoft.IdentityModel.Tokens.JsonWebKey` boundary exception blessed in the NetCrypto decisions.
- **Resolver-driven verification:** `DataProofsDotnet` defines a small resolver abstraction (working name `IVerificationMethodResolver`): verification-method URL → public key material plus controller metadata. Resolver-accepting overloads execute the full spec verification algorithm, including proof-purpose and controller validation. The interface lives *here*, so the dependency arrow points the right way: `net-did` implements it at a higher composition layer (wired in `credentials-dotnet`/`zcap-dotnet`, or via a thin adapter package owned outside this repo); this library never references `net-did`.

---

## 4. Public API posture

- The public surface speaks in this library's own proof and envelope types, `Multikey`, NetCrypto abstractions (`ISigner`, `IBbsCryptoProvider`), bytes/spans, and `System.Text.Json` types. The sanctioned exception, inherited from NetCrypto: `Microsoft.IdentityModel.Tokens.JsonWebKey` in JWK-facing APIs.
- No dotNetRDF, Newtonsoft, or any backend type appears in any public signature — including in the `Rdfc` package, whose public surface is suites and canonicalizers expressed in this library's types.
- `System.Text.Json` is the serialization standard everywhere; Newtonsoft exists only as a transitive, internal consequence of dotNetRDF inside `Rdfc`.
- Async signatures with `CancellationToken` where signing/resolution is involved, matching the `ISigner` shape.
- Developer examples follow the established convention: standalone console projects under `samples/`, no test frameworks, with public-API coverage mechanics to be specified in the PRD (per the NetCrypto FR-17 precedent).

---

## 5. Package layout (decision 5)

Consumer-aligned split, single repository, single version line, central package management — the machinery `net-did` already proves out:

| Package | Contents | Notable dependencies |
|---|---|---|
| `DataProofsDotnet.Core` | Proof models, Data Integrity pipeline, cryptosuite registry, JCS suites (`eddsa-jcs-2022`, `ecdsa-jcs-2019`), `IVerificationMethodResolver`, shared encoding helpers | NetCrypto, NetCid |
| `DataProofsDotnet.Jose` | JWS, JWE, JWT, JWK, SD-JWT + KB-JWT, SD-JWT VC, JOSE half of VC-JOSE-COSE | `Core` |
| `DataProofsDotnet.Cose` | COSE_Sign1, CWT, COSE half of VC-JOSE-COSE (`System.Formats.Cbor`) | `Core` |
| `DataProofsDotnet.Rdfc` | RDFC-1.0 + JSON-LD 1.1 canonicalization, RDFC suites (`eddsa-rdfc-2022`, `ecdsa-rdfc-2019`), `bbs-2023` | `Core`, **dotNetRDF (sole reference in the stack)** |
| `DataProofsDotnet.Extensions.DependencyInjection` | Registration helpers for the pipeline, suite registry, and resolvers | all of the above |

Consumer mapping kept honest: `didcomm-dotnet` → `Jose` only; `zcap-dotnet` → `Core` (+ `Rdfc` if it signs with RDFC suites); `credentials-dotnet` → all. Deferred items have a pre-assigned home: `ecdsa-sd-2023` lands in `Rdfc` without touching anything else.

---

## 6. Dependencies and isolation rules

- **Allowed runtime dependencies:** NetCrypto, NetCid, dotNetRDF (in `Rdfc` only), `Microsoft.IdentityModel.Tokens` (JWK exception only), BCL (`System.Formats.Cbor`, `System.Text.Json`), and the `Microsoft.Extensions.*` abstractions in the DI package.
- **Forbidden:** `net-did` (any package), `jose-jwt`, `Owf.Sd.Jwt`/SdJwt.Net at runtime, direct references to NSec/NBitcoin.Secp256k1/Nethermind — all crypto arrives through NetCrypto.
- **No cryptography is implemented in this repository.** If a primitive is missing, it is a NetCrypto work item, not a local shim.
- Runtime: .NET 10, central package management, repo conventions matching `net-did`/`didcomm-dotnet` (AGENTS.md, CLAUDE.md, samples, tasks).

---

## 7. Out of scope (v1)

- `ecdsa-sd-2023` — deferred (decision 3).
- Any cryptographic primitive implementation (NetCrypto's job).
- DID resolution and DID document handling (`net-did`'s job; only the resolver *interface* lives here).
- Credential data-model validation, status lists, presentation exchange (`credentials-dotnet`'s job).
- ZCAP and DIDComm protocol semantics (their libraries' jobs; this library provides the securing formats only).
- **Any change to a sibling repository is out of scope** (`net-did`, `didcomm-dotnet`, `zcap-dotnet`, `crypto-dotnet`) — mirroring NetCrypto decision 11. How each is *leveraged* differs and is not uniform: `crypto-dotnet` is consumed as a dependency, never copied; `zcap-dotnet` (embedded pipeline) and `didcomm-dotnet` (JOSE) are code-and-test porting sources per §1.3; `net-did` contributes its proof-record model (copied into `Core`) and its DID-method resolution (leveraged at net-did's own layer via the resolver interface, §8), not a bulk pipeline copy. In all cases the source repositories are read-only here.
- JSON-LD context publication/hosting, and advanced document-loader caching strategy (TTL/eviction tuning, shared/distributed caches) beyond the decided offline-default loader plus opt-in network loader (FR-10).

---

## 8. Downstream adoption (separately tracked — not part of this library's PRD)

Recorded so the shape isn't lost; each executes in its own repository, sequenced after `DataProofsDotnet` v1 ships:

1. **`didcomm-dotnet`** deletes `src/DidComm.Core/Jose/` and consumes `DataProofsDotnet.Jose`. Its existing tests are the behavior-parity oracle for the ported JWS/JWE code.
2. **`zcap-dotnet`** retires `ZcapLd.Core/Cryptography` (its proof pipeline, canonicalizers, suites, signature verifier, context loader) in favor of `DataProofsDotnet.Core` + `.Rdfc`, keeping only its ZCAP-specific document models and capability-chain logic. This is the reciprocal of porting *from* it: the proven mechanics move into `DataProofsDotnet` (where they are generalized, conformance-upgraded to the 2022/2019 suites, and put behind `ISigner`), then zcap consumes them back — preserving and upgrading the investment rather than maintaining two copies. Requires zcap to move from the 2020-era suites to the `DataIntegrityProof` generation, a versioning decision for that repository.
3. **`net-did`** retires `NetDid.Core/Crypto/DataIntegrity/` in favor of `DataProofsDotnet.Core`'s conformant `eddsa-jcs-2022`, and is a natural home for an `IVerificationMethodResolver` implementation (and adapter package) that other consumers compose — which is how net-did's `did:key` handling is leveraged. First requires resolving whether did:webvh log signing needs the spec-conformant suite or the current document-hash variant (a conformance question filed in `net-did`'s backlog).
4. **`credentials-dotnet`** is born consuming this library (it does not yet exist); no adoption refactor, but its concept document declares its package subset per §5.

---

## 9. Decisions log

| # | Decision | Ruling | Rationale |
|---|---|---|---|
| 1 | Crypto routing / build-vs-reuse for enveloping proofs | Implement envelope formats natively over NetCrypto; port `didcomm-dotnet` JWS/JWE as seed; `jose-jwt` and `Owf.Sd.Jwt` are dev-time test oracles only | Code audit: `jose-jwt`'s closed `JwsAlgorithm` enum lacks EdDSA and ES256K (forking required); both libraries require surrendered key material, incompatible with `IKeyStore`-held keys; wrapping them (anywhere, including inside `crypto-dotnet`) relocates rather than eliminates the second crypto path and inverts the layering. |
| 2 | v1 scope | Full §3 surface (option A): all four EdDSA/ECDSA suites, `bbs-2023`, full JOSE side incl. SD-JWT VC, full CBOR side (COSE_Sign1, CWT), both VC-JOSE-COSE halves | Complete layer in one release. Pre-final specs (`bbs-2023` CRD, SD-JWT VC I-D) pinned by version with churn risk logged, per the NetCrypto BBS-draft precedent. |
| 3 | `ecdsa-sd-2023` | Deferral stands | Redundant capability with weaker privacy than `bbs-2023` (linkable derived proofs) at comparable build cost; its real-world justification is FIPS-constrained selective disclosure, ruled out near-term by NetCrypto's Posture-1 decision. **Revisit trigger:** a FIPS requirement materializing — re-enter verify-first. Home pre-assigned: `Rdfc` package. |
| 4 | Verification key acquisition | Dual surface: raw-key primitives + resolver-driven full verification; `IVerificationMethodResolver` defined in this library; `Multikey` canonical | Keeps the `net-did` arrow pointing the right way (it implements; this library never references it); matches the stack's existing resolver idiom (`ISecretsResolver` in DIDComm) and NetCrypto's raw-bytes/`ISigner` duality. |
| 5 | Package layout | Consumer-aligned five-package split; `Rdfc` is the sole dotNetRDF reference in the stack | Honest consumer dependency graphs (`didcomm-dotnet` doesn't inherit an RDF stack to build a JWE); matches the `net-did` multi-package convention; deferred suites have a pre-assigned home. |
| 6 | Naming | PackageId/namespace root `DataProofsDotnet` | Maps one-to-one to the repository name. Deliberate divergence from the `Net*` family (`NetCid`, `NetDid`, `NetCrypto`), accepted by the owner. Exact-ID availability on nuget.org to be confirmed at repo creation; no collision found by search on 2026-06-10. |
| 7 | CBOR encoding (default, unchallenged) | BCL `System.Formats.Cbor` | CBOR excluded from `crypto-dotnet` by prior decision; zero-dependency, in-runtime; shared by COSE/CWT and `bbs-2023` `proofValue`. |

---

## 10. Success criteria

**Package-level (v1 — verified inside `dataproofs-dotnet` by the PRD):**

1. Each shipped cryptosuite passes the test vectors of its governing specification, and the RDFC/JCS suites verify the fixtures of the corresponding W3C interop test suites (`vc-di-eddsa`, `vc-di-ecdsa`, `vc-di-bbs`); `bbs-2023` base and derived proofs round-trip against the pinned CRD.
2. JOSE outputs cross-verify with the interop oracles for overlapping algorithms (a JWS/JWE produced here verifies in `jose-jwt` and vice versa, for algorithms both support); EdDSA and ES256K paths are covered by RFC 8037 / RFC 8812 vectors. SD-JWT and KB-JWT round-trip against RFC 9901 examples and `Owf.Sd.Jwt` cross-checks.
3. The ported JWS/JWE code passes the test suite copied in from `didcomm-dotnet`, unmodified in assertion content — the behavior-parity oracle.
4. COSE_Sign1 and CWT pass RFC 9052 / RFC 8392 examples.
5. Dependency hygiene is mechanically verified in CI: no package other than `Rdfc` has dotNetRDF (or transitive Newtonsoft) in its closure; no package references `net-did`, `jose-jwt`, or SdJwt.Net; no public API exposes a backend type (API-surface review), excepting the blessed `JsonWebKey`.
6. A signer backed by a non-exporting `IKeyStore` can produce every signature-bearing artifact in the library (Data Integrity proofs, JWS, SD-JWT, COSE_Sign1) — proving the no-key-surrender property end to end.

**Program-level (proven by separately tracked adoption items, §8):**

7. `credentials-dotnet`, `zcap-dotnet`, and `didcomm-dotnet` can declare all proof and envelope needs against `DataProofsDotnet` packages alone.
8. `didcomm-dotnet` ships a release with its internal `Jose/` folder deleted, tests unchanged.
9. `net-did` resolves its did:webvh proof-conformance question and retires its local engine.

---

## 11. Risks and open items

- **Pre-final specs in v1:** `bbs-2023` (W3C CRD, 2026-04-07 snapshot) and SD-JWT VC (`draft -16`) may change normatively. Mitigation: versions pinned in §2 and re-pinned at PRD time (2026-06-10 — BBS to the 2026-04-07 CRD; SD-JWT VC -16 confirmed latest), draft-sensitive logic isolated behind the suite registry and profile types, and per-phase re-verify / normative-diff checkpoints (BBS at Phase E, SD-JWT VC at Phase C).
- **The 1.1 track:** Data Integrity 1.1 and the EdDSA/ECDSA 1.1 cryptosuites (WDs, April 2026) accompany VCDM 2.1. v1 targets the 1.0 Recommendations; the suite registry must not preclude registering 1.1 revisions side by side.
- **dotNetRDF as a load-bearing dependency:** JSON-LD 1.1 + RDFC-1.0 correctness is delegated to it inside `Rdfc`. Its conformance against the RDFC-1.0 test suite is verified by our own fixture runs (criterion 1), not assumed.
- **`bbs-2023` is the long pole** (per the architecture build-vs-reuse analysis): the only suite combining RDFC machinery, HMAC relabeling, CBOR structures, and the BBS primitive. Phasing within the PRD should sequence it after the four EdDSA/ECDSA suites prove the pipeline.
- **JSON-LD document loading:** verification of RDFC suites requires `@context` retrieval. Policy decided at PRD time (FR-10): a pluggable loader with an **offline-only default** — embedded, provenance-tracked core contexts, fail-closed on the unknown — plus an opt-in caching network loader; the same offline-default / opt-in posture governs SD-JWT VC `vct` type-metadata retrieval. No residual ambient network I/O in the default verification path.
- **`architectural-path.md` reconciliation:** §5.3 currently says the migration of `eddsa-jcs-2022` from `net-did` is a relocation; this concept supersedes that with build-fresh-to-spec (reference-only seed). Folded into the already-pending reconciliation pass alongside the `crypto-dotnet` → `net-cid` dependency fix and the five-package layout.
