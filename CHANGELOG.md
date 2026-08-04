# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-08-04

### Fixed

- **`JwsBuilder` no longer duplicates the signer `kid` in both the protected and unprotected
  JWS headers** (issue #17). Both JSON serializations (Flattened and General) rendered a
  per-signature unprotected `"header": {"kid": ...}` object carrying the same `kid` already
  stamped into the integrity-protected header, violating RFC 7515 §7.2's requirement that the
  two header parameter-name sets be disjoint. Strict verifiers enforce this — nimbus-jose-jwt
  (used by didcomm-jvm) rejected every such JWS, blocking DIDComm v2.1 live-interop for the
  `signed` and `anoncrypt(sign)` compositions downstream. The `kid` is now **protected-only**
  (the conservative placement: it stays under the signature, and it is where `JwsParser` has
  preferred to read it since #10); the unprotected `header` object is no longer emitted at all.
  Round-trip behavior is unchanged — `JwsParser` already falls back to the protected header's
  `kid` when no unprotected one is present. Regression tests pin protected/unprotected
  parameter-set disjointness for both serializations. Wire-format note for consumers that
  inspected the envelope JSON directly: single- and multi-signature outputs with a kid-bearing
  signer no longer contain a `header` member (kid-less output is byte-identical to before).

## [1.1.1] - 2026-07-27

### Added

- **Samples now cover the opaque-key (HSM / KMS / keychain) JWE flow** — a new section in
  `samples/DataProofsDotnet.Samples.Jwe` exercising `IEcdhKey`, the shipped `RawEcdhKey` handle, a
  worked custom `IEcdhKey` implementation standing in for a device-backed key, and the async
  `JweBuilder.BuildEcdh1PuA256KwAsync` / `JweParser.ParseAsync` / `JweParser.ParseCompactAsync`
  overloads. These eight public members shipped in **1.1.0** (issue #13) with no sample, which left
  the **`ac-9` samples-coverage gate (FR-21 / AC-9) red on `main`** and blocked the release
  checklist's "all AC gates green" precondition. Coverage is back to **100%** (540/540 public
  members, 0 allowlisted). The sample also demonstrates that ECDH-1PU invokes the handle **twice**
  per decrypt (`Ze` against the ephemeral, then `Zs` against the sender's static key).

### Security

- **Transitive `AngleSharp` lifted 1.4.0 → 1.6.0** (via a direct floor-lift reference in
  `DataProofsDotnet.Rdfc`, the sole `dotNetRdf.Core` consumer) to clear the newly published
  [GHSA-pgww-w46g-26qg](https://github.com/advisories/GHSA-pgww-w46g-26qg) mXSS advisory
  (< 1.5.0), which failed the repo-wide NuGet audit (`NU1902` as error) and blocked every
  restore. Supply-chain hygiene only: this stack never parses HTML — AngleSharp rides in for
  dotNetRDF's HTML/RDFa readers, which DataProofs does not use. Remove the floor-lift when
  dotNetRdf.Core's own AngleSharp floor reaches 1.5.0+.

### Fixed

- **`JwsParser` now rejects a non-string unprotected `header.kid` as `MalformedJoseException`
  instead of leaking a raw `InvalidOperationException`** (issue #15). Both raw-signature
  enumeration sites (Flattened and General JSON serializations) read the unprotected header's
  `kid` with `JsonElement.GetString()` without a `ValueKind` guard, so a JWS carrying
  `"header": {"kid": 123}` (or an object/array/boolean) escaped the parser as an untyped fault —
  bypassing every `catch (MalformedJoseException)` in consumers. This was reachable
  **pre-authentication**: the read happens during structural enumeration, before any signature
  check, so any peer able to deliver bytes could throw it (downstream, a single crafted message
  tore down a didcomm-dotnet WebSocket receive loop — `didcomm-dotnet#58`). The strict option
  was chosen: any present non-string `kid` — including JSON `null` — is malformed per RFC 7515
  §4.1.4. It now throws
  `MalformedJoseException("JWS unprotected header 'kid' must be a string.")`; silently ignoring it
  would hide a broken sender. An absent unprotected `kid` still falls back to the protected
  header's `kid`, and a valid string `kid` behaves as before.
  Severity is availability/robustness — no signature is accepted, no key material is exposed.
- **`JwsParser` now wraps the top-level `JsonDocument.Parse` so malformed JSON surfaces as
  `MalformedJoseException`** (issue #15, adversarial follow-up). The JSON-serialization entry point
  parsed attacker-supplied bytes without a `catch`, so a truncated frame, trailing junk, a duplicate
  member, or over-deep nesting escaped `JwsParser.Parse` as a raw `System.Text.Json.JsonException` —
  the same "untyped fault escapes pre-verification" failure class as the `kid` bug above, and more
  reachable (any partial WebSocket frame is malformed JSON). `JweParser.ParseStructure` and
  `JwtClaims.Parse` already wrap this call; `JwsParser` now matches them, throwing
  `MalformedJoseException("JWS is not valid JSON.")`.

## [1.1.0] - 2026-06-22

### Security

- **`JweParser.Parse` is now constant-work with respect to recipient-key possession** (issue #12).
  Previously the parser fast-failed **before any ECDH** when no recipient `kid` matched a held
  private key, so "key held" vs "key not held" was observable as a response-time difference — a
  **recipient-key enumeration oracle** for any consumer that decrypts attacker-supplied JWEs and
  exposes a timing-observable result (the root cause of downstream `didcomm-dotnet#35`). The parser
  now routes the non-decryptable case through a per-process **decoy** ECDH key on the envelope's
  work curve, performing the same key-agreement / key-unwrap work and then failing uniformly at
  unwrap. The decision keys on *"is a held key present that matches the envelope's `epk` curve?"* —
  not merely *"is the `kid` held?"* — which also closes a residual leak where a held key on the
  **wrong curve** fast-failed before the ECDH. Decoy keys are generated **once per process and
  cached** (a per-call key generation would itself re-introduce a timing signal). The successful
  decrypt path of a curve-matching held key is unchanged and pays nothing extra. **No public API
  change.**
  - **Scope:** this makes the parser's *own* post-resolution path constant-work for a fixed
    `(alg, enc, epk-curve)`. A fully constant-time decrypt additionally requires the supplied
    `IJweRecipientKeyResolver` (`FindPresent`/`TryGet`) to be timing-independent of which kids are
    held — that contract is outside the parser and remains the caller's responsibility.

### Added

- **Async `IEcdhKey` seam for opaque (HSM/keystore) ECDH keys** (issue #13). A new additive
  `IEcdhKey` handle (`Crv` + `DeriveAsync`) lets the JWE key-agreement step run on a private key
  that **never exposes its scalar** — HSM, cloud KMS, OS keychain, or `NetCrypto.IKeyStore` — while
  `DataProofsDotnet.Jose` stays DID-agnostic (the handle carries only a curve and a derive
  callback). New async overloads `JweParser.ParseAsync` / `ParseCompactAsync` (recipient supplied as
  an `IEcdhKey`) and `JweBuilder.BuildEcdh1PuA256KwAsync` (opaque sender static key; the per-message
  ephemeral stays raw) drive full **authcrypt (ECDH-1PU)** and **anoncrypt (ECDH-ES)** flows. The
  shipped `RawEcdhKey` wraps in-process key bytes and reproduces the existing conformance vectors
  **byte-for-byte**; opaque implementations live downstream over `IKeyStore.DeriveSharedSecretAsync`
  (raw `Z`). The existing **synchronous JWE API is unchanged** (back-compat), and the new async path
  carries the same issue #12 constant-work decoy defense.

## [1.0.1] - 2026-06-16

### Fixed

- **`JwsParser` now reports the verified signer `kid` when it is carried only in the JWS
  unprotected header** (issue #10). The parser already resolves the verifying key from the
  per-signature unprotected `header.kid` and verifies against it, but previously returned
  `JwsParseResult.SignerKid == ""` whenever the integrity-protected header carried no `kid` —
  discarding the very identity the signature proved. `SignerKid` is now the `kid` that resolved
  the key under which the signature verified (the protected header is preferred when present;
  otherwise the unprotected `kid` is reported). This is sound because verification has already
  succeeded: a rewritten unprotected `kid` resolves a different key under which the signature
  cannot verify, so a forged `kid` never reaches the result. This corrects an over-conservative
  decision from the issue #6 hardening pass (Finding #2) and unblocks **DIDComm Messaging v2.1**
  signed and `authcrypt(sign(...))` conformance, which places the signer `kid` in the unprotected
  JWS header (the five Appendix C.2/C.3 interop vectors that previously failed). Unchanged:
  a `kid` in the protected header is still reported as before, and a JWS whose protected and
  unprotected `kid` **disagree** is still rejected (`MalformedJoseException`).

## [1.0.0] - 2026-06-14

### Added

- **`DataProofsDotnet.Legacy`** — a new opt-in package shipping the pre–Data-Integrity
  **Linked-Data-Signature** cryptosuites `Ed25519Signature2020` and
  `EcdsaSecp256r1Signature2019` (issue #7, FR-4). Each implements `ICryptosuite` and supports
  both a **JCS** variant (the back-compat default — the document with the proof nested under a
  `proof` member, JCS-canonicalized once) and an **RDFC-1.0** variant
  (`SHA-256(RDFC(proofOptions)) ‖ SHA-256(RDFC(document))`). The emitted proof carries
  `type:"<suite>"`, **no `cryptosuite`**, and a base58-btc `proofValue`; it create→verify
  round-trips through `DataIntegrityProofPipeline` (create dispatches by `cryptosuite` naming the
  suite; verify dispatches by `type` via `GetByProofType`). The suites are **not** registered in
  `CryptosuiteRegistry.CreateDefault()` — register them explicitly. The wire convention and
  signing bytes are **byte-identical to zcap-dotnet**, locked by a cross-stack golden vector
  (a zcap-issued `Ed25519Signature2020` proof verifies, and re-signing reproduces zcap's exact
  `proofValue`). Unmodeled proof members (e.g. `capabilityChain`) ride through
  `DataIntegrityProof.AdditionalProperties` into the JCS signing input. This unblocks
  zcap-dotnet's proof-pipeline delegation and legacy-VC verification in credentials-dotnet.
    - **Use legacy suites only for interop with existing corpora; prefer the 2022/2019 Data
      Integrity suites for new proofs.**
    - **Documented limitations** (verified by adversarial review): the JCS variant has no
      representation for a W3C proof chain and **fails closed** if asked to secure/verify a
      document that already carries a `proof` member (use the RDFC variant or a 2022/2019 suite
      for chains); the RDFC variant binds only terms defined in the active JSON-LD `@context`
      (members it does not define are dropped by RDF expansion — inherent to JSON-LD/RDFC, shared
      with the conformant `rdfc-*` suites); and `EcdsaSecp256r1Signature2019` does not enforce
      low-`s`, so ECDSA `proofValue`s are malleable and must not be used as unique identifiers.
- **JOSE explicit typing (RFC 8725 §3.11).** `JwtValidationOptions.ExpectedType` (opt-in) pins the
  JWS protected `typ` header on `JwtHandler.Verify` (case-insensitive, `application/`-prefix
  tolerant), rejecting cross-context token confusion; default behavior is unchanged. The verified
  `typ` is now surfaced on `JwsParseResult.Typ`.

### Changed

- **`Base64Url.Decode` is now strict (behavioral change).** It rejects any input outside the
  base64url-no-pad alphabet — including interior/surrounding ASCII whitespace, `=` padding, and the
  standard-base64 `+`/`/` — by throwing `FormatException`, where the previous implementation
  silently tolerated them. This matches the documented "valid base64url" contract and the JOSE
  no-pad requirement, but an out-of-repo caller that previously passed padded or whitespace-bearing
  input will now get a `FormatException`. **Upgraders:** scan your `Base64Url.Decode` call sites for
  non-canonical input. (Also tracked under Security below — it closes an encoding-ambiguity gap.)
- **Bumped the `NetCrypto` dependency from 1.0.0 to 1.1.0** across all packages. The library
  source is unaffected; consumers resolve NetCrypto ≥ 1.1.0 transitively. (1.1.0 also introduces a
  `NetCrypto.Base64Url` type — when a consumer imports both `NetCrypto` and `DataProofsDotnet.Jose`,
  reference `Base64Url` via a `using` alias or fully-qualified name to disambiguate it from
  `DataProofsDotnet.Jose.Base64Url`.)

### Security

- **JOSE hardening pass (issue #6).** An adversarial multi-agent review of the entire
  `DataProofsDotnet.Jose` surface (JWS/JWE/ECDH-1PU/JWK/SD-JWT/JWT/encoding), with every finding
  put through independent majority-vote verification, produced these fixes (each pinned by a
  regression test in `Hardening/HardeningRegressionTests.cs`):
    - **SD-JWT reconstruction now fails closed on a deep recursive-disclosure chain.**
      `SdJwtReconstructor` walked the disclosed payload by unbounded mutual recursion; a chained
      recursive-disclosure presentation (RFC 9901 §6.3) rooted in an issuer-signed `_sd` digest could
      drive it into an **uncatchable `StackOverflowException` that terminates the host process**,
      defeating the verifier's fail-closed contract. Reconstruction is now depth-bounded (64, matching
      the JSON parse depth) and raises a `MalformedJoseException` (surfaced as `DISCLOSURE_INVALID`).
    - **A malformed/unsupported `cnf` (or issuer) key no longer crashes SD-JWT verification.**
      `CompactJwt.Verify` mapped an unsupported curve / off-curve key point to an uncaught
      `NotSupportedException`/crypto exception (reachable through an attacker-influenced `cnf` on the
      Key Binding path); it now fails closed as `MalformedJoseException`, which both call sites handle.
    - **JWS reports the verified signer only from integrity-protected material.** `JwsParseResult
.SignerKid` is now sourced solely from the protected header; a `kid` carried only in the
      unauthenticated unprotected header is treated as a routing hint and never surfaced as the
      verified identity. Verification of valid JWS (including `kid`-in-unprotected) is unchanged.
    - **`Base64Url.Decode` is now strict** — it rejects interior/surrounding whitespace, `=` padding,
      and standard-base64 `+`/`/`, matching the documented base64url-no-pad contract.

## [0.1.0-preview.2] - 2026-06-13

### Added

- **`ICryptosuite.SupportedProofTypes`** — a default interface member (defaults to the single
  `DataIntegrityProof` type) by which a suite declares the proof `type`(s) it verifies. Existing
  suites are unaffected and continue to be dispatched by `cryptosuite` name.
- **`CryptosuiteRegistry.GetByProofType(string?)`** — resolves a legacy/type-named suite by its
  declared proof `type`, backed by a secondary `type → suite` index that excludes the default
  Data Integrity type (so the JCS suites stay unambiguous and name-dispatched).

### Fixed

- **Verify pipeline can now dispatch legacy / type-named proofs (issue #4, FR-4).** The verify
  path previously dispatched a proof to a cryptosuite only when it carried a `cryptosuite` member
  **and** `type == "DataIntegrityProof"`, making it impossible to register a suite that verifies
  pre–Data-Integrity Linked-Data-Signature proofs (`Ed25519Signature2020`,
  `EcdsaSecp256r1Signature2019`, …) — which name their algorithm by `type` and carry no
  `cryptosuite`. The pipeline could therefore emit (via a custom suite) a legacy-shaped proof it
  then refused to verify. Dispatch now falls back to the proof `type` when no `cryptosuite` is
  present (`cryptosuite`-named suites still always win), closing the create→verify inconsistency
  and honoring the FR-4 "registering a new suite requires no pipeline changes" contract. The
  library still **creates** only conformant 2022/2019 proofs; this is verification-only and
  non-breaking. Suite selection only _routes_ — each suite still fully validates
  `type`/`cryptosuite`/key/encoding/signature. Regression tests in
  `LegacyProofTypeVerificationTests` and `CryptosuiteRegistryTests`.

## [0.1.0-preview.1] - 2026-06-13

First preview release of all five packages (`Core`, `Jose`, `Cose`, `Rdfc`,
`Extensions.DependencyInjection`) — a NuGet prerelease for validation.

### Added

- **Repository scaffold**: five-package solution (`Core`, `Jose`, `Cose`, `Rdfc`,
  `Extensions.DependencyInjection`), central package management, PublicApiAnalyzers on every
  package from the first commit (FR-24), vendored conformance fixtures with provenance
  tracking, and CI per `dataproofs-prd.md` §9.

### Security

- **`bbs-2023` mandatory disclosure is now cryptographically enforced.** The mandatory-disclosure
  group is bound into the BBS signature `header` (`SHA-256(proofConfig) ‖ SHA-256(mandatory
N-Quads)`) at sign and derive, and the header is recomputed at verify from the revealed
  mandatory messages — so a holder that drops or alters a mandatory statement produces a header
  that no longer matches the one the proof commits to, and verification fails. Closes the
  adversarial-review finding that a holder could omit a mandatory claim and still verify. Requires
  NetCrypto ≥ 1.0.0 (the BBS `header` parameter, upstream moisesja/crypto-dotnet#2; first
  available in 1.0.0-preview.2, GA in 1.0.0); regression test
  `Verify_MandatoryStatementReclassifiedAsSelective_FailsClosed`.
