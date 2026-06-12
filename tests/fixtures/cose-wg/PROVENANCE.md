# Provenance: cose-wg/Examples (COSE_Sign1 vectors, v1 algorithm set)

- **Origin URL:** https://github.com/cose-wg/Examples
- **Git commit SHA:** `53c9d634333bb4f529d78f5980fffa2667ee2c12` (committed 2024-03-13, repository HEAD at retrieval)
- **Retrieved:** 2026-06-11 (shallow clone at HEAD)
- **License:** Unlicense / public domain (see `LICENSE`, copied verbatim from the repository root)
- **Consumed by:** AC-4 (PRD §9) — COSE/CWT conformance, verify-direction theories through `Cose` public APIs

## Local transformations

**None.** Every vendored file is a byte-identical copy of the upstream file at the
pinned commit (verified with `cmp` at vendoring time). Directory names mirror the
upstream layout.

## Selection rule

Per AC-4, the upstream repository is **filtered to COSE_Sign1 structures using the
v1 algorithm set: EdDSA (Ed25519 only), ES256, ES384, and ES256K if present**.
In the upstream JSON schema (`Examples.cddl`), COSE_Sign1 cases carry an
`input.sign0` member; multi-signer COSE_Sign cases carry `input.sign` and are out
of scope.

## Files taken (12 fixture files + LICENSE)

| File | Structure | Alg / curve | Kind |
|---|---|---|---|
| `sign1-tests/sign-pass-01.json` | COSE_Sign1 | ES256 / P-256 | positive (redo protected) |
| `sign1-tests/sign-pass-02.json` | COSE_Sign1 | ES256 / P-256 | positive (external AAD) |
| `sign1-tests/sign-pass-03.json` | COSE_Sign1 | ES256 / P-256 | positive (untagged) |
| `sign1-tests/sign-fail-01.json` | COSE_Sign1 | ES256 / P-256 | negative (wrong CBOR tag) |
| `sign1-tests/sign-fail-02.json` | COSE_Sign1 | ES256 / P-256 | negative (changed signature) |
| `sign1-tests/sign-fail-03.json` | COSE_Sign1 | ES256 / P-256 | negative (changed alg) |
| `sign1-tests/sign-fail-04.json` | COSE_Sign1 | ES256 / P-256 | negative (changed alg to unknown) |
| `sign1-tests/sign-fail-06.json` | COSE_Sign1 | ES256 / P-256 | negative (added protected attr) |
| `sign1-tests/sign-fail-07.json` | COSE_Sign1 | ES256 / P-256 | negative (removed protected attr) |
| `eddsa-examples/eddsa-sig-01.json` | COSE_Sign1 | EdDSA / Ed25519 | positive |
| `ecdsa-examples/ecdsa-sig-01.json` | COSE_Sign1 | ES256 / P-256 | positive |
| `ecdsa-examples/ecdsa-sig-02.json` | COSE_Sign1 | ES384 / P-384 | positive |

Note: `sign1-tests/sign-fail-05.json` does **not exist upstream** at the pinned
commit (the upstream numbering skips 05); it is not a dropped file.

Each fixture is self-contained: the signing/verification key (COSE_Key as JSON,
including the private part), protected/unprotected headers, intermediate
`ToBeSign_hex`, and the expected output (`cbor` hex and `cbor_diag`) are all
embedded in the JSON. No shared key file is required (the upstream root
`KeySet.txt` was therefore not vendored).

## Files filtered out, and why

- `eddsa-examples/eddsa-01.json`, `eddsa-examples/eddsa-02.json` — COSE_Sign
  (multi-signer `input.sign`), not COSE_Sign1; `eddsa-02` is additionally Ed448.
- `eddsa-examples/eddsa-sig-02.json` — COSE_Sign1 but Ed448; v1 EdDSA scope is
  Ed25519 only.
- `ecdsa-examples/ecdsa-01.json` … `ecdsa-04.json` — COSE_Sign, not COSE_Sign1.
- `ecdsa-examples/ecdsa-sig-03.json` — COSE_Sign1 but ES512 (P-521), outside the
  v1 algorithm set.
- `ecdsa-examples/ecdsa-sig-04.json` — COSE_Sign1 but ES512 over a P-256 key,
  outside the v1 algorithm set.
- All other upstream directories (`sign-tests`, MAC/encryption/ECDH/RSA/countersign
  families, `CWT`, `RFC8152`, `X25519-tests`, `x509-examples`, `hashsig`, etc.) —
  not COSE_Sign1 signature vectors in the v1 algorithm set. (CWT fixtures come
  from RFC 8392 Appendix A instead; see `tests/fixtures/ietf/rfc8392/`.)

**ES256K:** the upstream repository contains **no ES256K (secp256k1, COSE alg
-47) vectors at the pinned commit** — verified by case-insensitive search for
`ES256K`, `secp256k1`, `P-256K`, and the algorithm identifier `-47` (the only
`-47` substring hits are inside UUID `kid` values). ES256K COSE coverage must
come from generated-and-frozen vectors as for the JOSE half (PRD AC-3 pattern).

## Fixture counts (for count assertions)

- Total fixture files: **12**
- `sign1-tests/`: **9** (3 pass, 6 fail)
- `eddsa-examples/`: **1**
- `ecdsa-examples/`: **2**
- Per algorithm: ES256 ×10, ES384 ×1, EdDSA(Ed25519) ×1; ES256K ×0 (none exist upstream)
