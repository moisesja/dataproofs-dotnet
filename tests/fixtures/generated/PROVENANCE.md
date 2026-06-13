# Provenance — generated frozen vectors (ES256K, XC20P)

- **Origin:** generated locally by `tasks/generate-jose-vectors/` (this repository) via
  `tests/fixtures/generated/generate.sh`; **not** vendored from an external source.
- **Generation date:** 2026-06-12, against `DataProofsDotnet.Jose` at the Phase-B commit and
  `NetCrypto 1.0.0-preview.1`.
- **Why generated (PRD AC-3):** neither algorithm has a worked vector in an RFC nor coverage in
  the `jose-jwt` oracle —
  - **ES256K (RFC 8812):** RFC 8812 publishes no worked JWS vector, and `jose-jwt`'s closed
    `JwsAlgorithm` enum excludes ES256K, so the AC-3 oracle intersection cannot cover it.
  - **XC20P (draft-irtf-cfrg-xchacha-03):** not a registered JWA algorithm; absent from
    `jose-jwt`'s `JweEncryption` enum.
- **No external secp256k1 oracle (explicit note per AC-3):** the AC-3 contract asks for
  cross-verification "against an independent secp256k1 ECDSA implementation over the exact JWS
  signing input" at generation time. **No independent secp256k1 implementation is available in
  this stack**: the only secp256k1 code reachable here is NBitcoin.Secp256k1 — the very library
  NetCrypto wraps — so verifying against it would not be independent; .NET's platform crypto on
  this host (Apple Security framework) does not support the secp256k1 curve; and the `jose-jwt`
  oracle excludes ES256K. The vectors are therefore **self-generated regression pins**, with
  these compensating assurances:
  1. NetCrypto's secp256k1 signing is RFC 6979-deterministic; the generator signs twice and
     refuses to freeze on any divergence, and the test re-signs and byte-compares on every run —
     any drift in NetCrypto or the JWS composition fails CI.
  2. NetCrypto's secp256k1 primitive is itself vector-tested upstream in `crypto-dotnet`.
  3. The signature is verified (verify-direction) through the public `JwsParser` on every run.
- **XC20P assurance:** NetCrypto's `XChaCha20Poly1305Cipher` is validated upstream against the
  draft-irtf-cfrg-xchacha-03 vectors (via NSec/libsodium); the frozen AEAD KAT and JWE artifact
  here pin the JOSE composition (CEK/nonce sizes, AAD construction, tag handling) against
  regression.
- **Freezing policy:** the generator (`tasks/generate-jose-vectors/Program.cs`) refuses to
  overwrite existing files without `--force`. Re-pinning the vectors is a reviewable diff of
  this directory plus this file.

## Files

| File | Contents |
|---|---|
| `es256k-jws.json` | Fixed secp256k1 private/public JWK, payload, protected header, JWS signing input, deterministic signature, compact + flattened JWS forms. |
| `xc20p.json` | `aeadKat`: fixed key/nonce/AAD/plaintext → ciphertext/tag for XChaCha20-Poly1305. `frozenJwe`: a complete ECDH-ES+A256KW / XC20P General-JSON JWE with the recipient's fixed X25519 private JWK (decrypt direction is deterministic). |
| `generate.sh` | Regeneration entry point (delegates to `tasks/generate-jose-vectors/`). |
