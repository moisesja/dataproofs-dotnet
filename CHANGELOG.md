# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Repository scaffold**: five-package solution (`Core`, `Jose`, `Cose`, `Rdfc`,
  `Extensions.DependencyInjection`), central package management, PublicApiAnalyzers on every
  package from the first commit (FR-24), vendored conformance fixtures with provenance
  tracking, and CI per `dataproofs-prd.md` §9.

### Security

- **`bbs-2023` mandatory disclosure is not yet cryptographically enforced (experimental).** The
  W3C `bbs-2023` cryptosuite binds the mandatory-disclosure group into the BBS signature
  `header`; NetCrypto v1's BBS provider does not expose that parameter, so a holder can present a
  derived proof omitting a mandatory statement and it still verifies. Tracked in
  `docs/dependencies/netcrypto-bbs-header.md` (upstream moisesja/crypto-dotnet#2); the conformant
  binding lands once NetCrypto ships the `header` parameter. The other four cryptosuites and all
  enveloping proofs are unaffected.
