# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  non-breaking. Suite selection only *routes* — each suite still fully validates
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
