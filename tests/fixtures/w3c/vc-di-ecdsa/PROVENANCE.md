# Provenance — W3C Data Integrity ECDSA Cryptosuites v1.0 test vectors

Fixtures for PRD AC-1 (cryptosuite conformance), suites `ecdsa-rdfc-2019` and
`ecdsa-jcs-2019`, curves P-256 and P-384. The `ecdsa-sd-2023` suite is **out of
scope** for this package and its vectors were deliberately not vendored.

Retrieval date: **2026-06-11**.

## Sources

### 1. Governing specification (REC)

- Document: *Data Integrity ECDSA Cryptosuites v1.0*, W3C Recommendation
  15 May 2025.
- This-version URL: <https://www.w3.org/TR/2025/REC-vc-di-ecdsa-20250515/>
  (retrieved via <https://www.w3.org/TR/vc-di-ecdsa/>, which resolved to that
  REC on the retrieval date).

### 2. Spec repository `w3c/vc-di-ecdsa` → `spec/`

- Origin: <https://github.com/w3c/vc-di-ecdsa> (shallow clone at HEAD of `main`)
- Commit: `00781de52c036723bbd88d89b07818a2914a6b9e` (2026-04-08)
- Vendored path: the repository's `TestVectors/` directory is the
  machine-readable source of the REC's worked test-vector sections (spec §3.1
  representations and the "Test Vectors" walkthroughs for each suite).
- License: W3C Document License / W3C Software and Document License (per repo
  `LICENSE.md`).

**Cross-check against the published REC** (performed 2026-06-11 on the
downloaded REC HTML): for every vendored suite directory the `docHash`,
`proofHash`, `combinedHash`, `sigHex`, `sigBTC58` values and the final
`proofValue` in the `signed*.json` documents were grepped against
`REC-vc-di-ecdsa-20250515` HTML and **all matched** (≥1 occurrence each). The
`canonDoc*`/`proofCanon*` text files could not be byte-grepped only because the
HTML entity-escapes quote characters; their derived hashes matched. The repo
vectors at this commit are therefore the REC-20250515 vectors, unchanged.

### 3. Test-suite repository `w3c/vc-di-ecdsa-test-suite` → `test-suite/`

- Origin: <https://github.com/w3c/vc-di-ecdsa-test-suite> (shallow clone at
  HEAD of `main`)
- Commit: `1854b5402c362b9a9c3b70eb54a9e6e5d82bd190` (2026-01-13)
- License: BSD-3-Clause (per repo `LICENSE.md` / `LICENSES/`).
- Note: this suite is primarily a *live interop harness* (it signs/verifies
  against running implementations), so it carries few static vectors. Its key
  material config (`config/keys.json`) points at the spec repo's
  `TestVectors/p256KeyPair.json` / `p384KeyPair.json`, which are already
  vendored under `spec/` here.

## Layout and local transformations

```
spec/                                  ← w3c/vc-di-ecdsa @ 00781de, TestVectors/
  unsigned.json                          base unsigned credential (AlumniCredential, VCDM 2.0)
  employmentAuth.json                    second unsigned credential (employment authorization,
                                         input to the rdfc "employ/" vector sets)
  p256KeyPair.json                       P-256 Multikey pair (publicKeyMultibase/secretKeyMultibase)
  p384KeyPair.json                       P-384 Multikey pair
  ecdsa-rdfc-2019-p256/   (+ employ/)
  ecdsa-rdfc-2019-p384/   (+ employ/)
  ecdsa-jcs-2019-p256/
  ecdsa-jcs-2019-p384/
test-suite/                            ← w3c/vc-di-ecdsa-test-suite @ 1854b54
  mocks/valid/vc1.1/document.json        interop input credential (VCDM 1.1)
  mocks/valid/vc2.0/document.json        interop input credential (VCDM 2.0)
  extracted/signed-credential-ecdsa-jcs-2019-p256.json
  extracted/signed-credential-ecdsa-jcs-2019-p384.json
```

Each `spec/ecdsa-*-<curve>/` vector set (root and, for rdfc, `employ/`)
contains exactly 9 files using the spec repo's original names:

| File | Content |
|---|---|
| `canonDoc*.txt` | canonical form of the unsigned document (RDFC-1.0 N-Quads for rdfc; JCS canonical JSON for jcs) |
| `proofConfig*.json` | proof configuration / proof options (jcs configs include `@context` per the suite's rules) |
| `proofCanon*.txt` | canonical form of the proof configuration |
| `docHash*.txt` | hex SHA-256 (P-256) / SHA-384 (P-384) hash of the canonical document |
| `proofHash*.txt` | hex hash of the canonical proof configuration |
| `combinedHash*.txt` | hex `proofHash ‖ docHash` (the signed hash data) |
| `sigHex*.txt` | raw ECDSA signature, hex |
| `sigBTC58*.txt` | signature, base58btc |
| `signed*.json` | the complete signed credential with the expected `proof` (expected `proofValue`) |

Transformations applied (exhaustive):

1. `spec/`: byte-identical copies of `TestVectors/` files; the four suite
   directories and four top-level input/key files only. **Excluded** as
   out-of-scope (ecdsa-sd-2023 only): `TestVectors/ecdsa-sd-2023/**`,
   `SDKeyMaterial.json`, `employMandatory.json`, `employSelective.json`,
   `prCredUnsigned.json`, `prCredMandatory.json`, `prCredSelective.json`.
2. `test-suite/mocks/**`: byte-identical copies of
   `tests/mocks/valid/vc{1.1,2.0}/document.json`. The sibling
   `mandatoryPointers.json` / `selectivePointers.json` files were excluded
   (used only by the ecdsa-sd-2023 tests), as were `tests/mocks/achievement/**`
   (sd-only).
3. `test-suite/extracted/*.json`: extracted on 2026-06-11 from the JavaScript
   object literals `ecdsaJcsVectors['P-256']` and `ecdsaJcsVectors['P-384']`
   in `tests/vectors.js` by importing the module in Node.js and serializing
   with `JSON.stringify(v, null, 2)`. These are *independently generated*
   valid `ecdsa-jcs-2019` signed credentials (ECDSA is randomized, so their
   `proofValue`s differ from `spec/ecdsa-jcs-2019-*/signedJCS*.json`); they
   serve as extra verify-direction fixtures. The suite's
   `ecdsaRdfcVectors['P-256'|'P-384']` literals were **not** extracted because
   they are value-identical (same `proofValue`) to
   `spec/ecdsa-rdfc-2019-*/signed*.json` already vendored here.
4. No other edits: no reformatting, renaming of contents, re-serialization, or
   whitespace changes were applied to any copied file.

## Fixture counts

CI count assertions should check these totals (AC-2-style count guard):

| Directory | Files |
|---|---|
| `spec/` top-level inputs + keys | 4 |
| `spec/ecdsa-rdfc-2019-p256/` (9 root + 9 `employ/`) | 18 |
| `spec/ecdsa-rdfc-2019-p384/` (9 root + 9 `employ/`) | 18 |
| `spec/ecdsa-jcs-2019-p256/` | 9 |
| `spec/ecdsa-jcs-2019-p384/` | 9 |
| `test-suite/mocks/` | 2 |
| `test-suite/extracted/` | 2 |
| **Total fixture files (excluding this PROVENANCE.md)** | **62** |
