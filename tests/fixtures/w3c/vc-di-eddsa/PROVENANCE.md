# Provenance — W3C Data Integrity EdDSA Cryptosuites v1.0 test vectors

Retrieval date: **2026-06-11**

## Sources

### 1. Spec test vectors (`TestVectors/`)

- Origin repository: <https://github.com/w3c/vc-di-eddsa>
- Git commit SHA (HEAD at retrieval, shallow clone): `45d646b1422bbbb227f29b8698757b8b78342305`
- Repository path copied: `TestVectors/` (entire directory, **verbatim — no transformation, original filenames and bytes preserved**)
- Governing specification: *Data Integrity EdDSA Cryptosuites v1.0*, W3C Recommendation 15 May 2025
  - This version: <https://www.w3.org/TR/2025/REC-vc-di-eddsa-20250515/>
  - Latest version: <https://www.w3.org/TR/vc-di-eddsa/>

These files are the machine-readable source of the worked test vectors embedded in
the Recommendation's test-vector sections (§3.1 Representation: eddsa-rdfc-2022 and
§3.2 Representation: eddsa-jcs-2022 example blocks, and the proof set/chain examples).
At retrieval time the repository copy was **verified against the published REC HTML**
(fetched 2026-06-11 from <https://www.w3.org/TR/vc-di-eddsa/>, which resolved to
REC-vc-di-eddsa-20250515): every `proofValue`, the key-pair multibase values, all
document/proof/combined SHA-256 hash hex strings, the signature hex/base58btc strings,
and spot-checked canonical N-Quads lines (modulo HTML entity escaping of `<`/`>`)
appear byte-identically in the REC HTML.

### 2. Test-suite repository (`test-suite/`)

- Origin repository: <https://github.com/w3c/vc-di-eddsa-test-suite>
- Git commit SHA (HEAD at retrieval, shallow clone): `769275c968c608799939aa25bb32869ce76a8e10`
- The repository contains **no static signed-document or key fixtures**: it is a live
  interop harness that generates credentials at run time against implementation
  endpoints (see Gaps below). The only static input document it carries is the
  credential template in `tests/vc-generator/validVc.js`.
- `test-suite/valid-vc.json` — **transformation applied**: the JavaScript object
  literal exported from `tests/vc-generator/validVc.js` was converted to strict JSON
  (single quotes → double quotes, keys quoted). No values were altered.

## File inventory and counts

Total fixture files: **56** (55 verbatim under `TestVectors/` + 1 extracted under `test-suite/`).

### `TestVectors/` root — shared inputs (3 files)

| File | Description |
| --- | --- |
| `unsigned.json` | Unsigned AlumniCredential (input document for both suites) |
| `keyPair.json` | Ed25519 key pair: `publicKeyMultibase` (`z6MkrJVnaZke…`) + `privateKeyMultibase` (seed, `z3u2en7t5LR2…`) |
| `employmentAuth.json` | Unsigned employment-authorization credential (input for the second eddsa-rdfc-2022 worked example) |

### `TestVectors/eddsa-rdfc-2022/` — 9 files + `employ/` 9 files = 18

AlumniCredential worked example (9 files):

| File | Description |
| --- | --- |
| `proofConfigDataInt.json` | Proof options/configuration (with `@context`) |
| `canonDocDataInt.txt` | RDFC-1.0 canonical N-Quads of the unsigned document |
| `proofCanonDataInt.txt` | RDFC-1.0 canonical N-Quads of the proof configuration |
| `docHashDataInt.txt` | SHA-256 hash of canonical document (hex) |
| `proofHashDataInt.txt` | SHA-256 hash of canonical proof config (hex) |
| `combinedHashDataInt.txt` | Concatenated hash data = proofHash ∥ docHash (hex) |
| `sigHexDataInt.txt` | Ed25519 signature (hex) |
| `sigBTC58DataInt.txt` | Signature, base58btc |
| `signedDataInt.json` | Expected signed credential (proof with `proofValue` `z2YwC8z3ap7…`) |

`employ/` — same 9-file set for the employment-authorization document (expected
`proofValue` `zeuuS9pi2ZR…`).

### `TestVectors/eddsa-jcs-2022/` — 9 files

Same 9-file structure with `JCS` suffix: `proofConfigJCS.json`, `canonDocJCS.txt`
(JCS canonical JSON), `proofCanonJCS.txt`, `docHashJCS.txt`, `proofHashJCS.txt`,
`combinedHashJCS.txt`, `sigHexJCS.txt`, `sigBTC58JCS.txt`, `signedJCS.json`
(expected `proofValue` `z2HnFSSPPBz…`).

### `TestVectors/Ed25519Signature2020/` — 9 files

Same 9-file structure (`…EdSig` suffix) for the legacy Ed25519Signature2020 suite
also defined in the REC (expected `proofValue` `z57Mm1vboMt…`). Vendored for
completeness of the spec's vector set; not required by AC-1's deterministic-suite
list (`eddsa-rdfc-2022`, `eddsa-jcs-2022`).

### `TestVectors/proof-set-chain/` — 16 files

Worked proof-set and proof-chain vectors (eddsa-rdfc-2022, REC §2 / FR-6 material):

| File | Description |
| --- | --- |
| `unsigned.json` | Unsigned input credential for set/chain examples |
| `multiKeyPairs.json` | Multiple Ed25519 key pairs (multibase secret + public) for the set/chain signers |
| `proofSetConfig1.json`, `proofSetConfig2.json` | Proof options for the two independent set proofs |
| `proofSetConfigSigned1.json`, `proofSetConfigSigned2.json` | Each set proof signed individually |
| `signedProofSet1.json`, `signedProofSet2.json` | Document carrying the proof set (incremental, then both proofs) |
| `proofChainConfig1.json`, `proofChainConfig2.json` | Proof options for chain links (link 2 uses `previousProof`) |
| `proofChainTempDoc1.json`, `proofChainTempDoc2.json` | Intermediate documents used as chain signing input |
| `proofChainConfigSigned1.json`, `proofChainConfigSigned2.json` | Each chain proof signed |
| `signedProofChain1.json`, `signedProofChain2.json` | Document with chain proof 1, then full chain |

### `test-suite/` — 1 file

| File | Description |
| --- | --- |
| `valid-vc.json` | Credential template from `vc-di-eddsa-test-suite` `tests/vc-generator/validVc.js` (JS→JSON conversion as noted above) |

## Count assertions

For tests that assert fixture counts against this file:

- `TestVectors/` verbatim files: **55**
- `TestVectors/eddsa-rdfc-2022/` (including `employ/`): **18**
- `TestVectors/eddsa-jcs-2022/`: **9**
- `TestVectors/Ed25519Signature2020/`: **9**
- `TestVectors/proof-set-chain/`: **16**
- Shared root inputs: **3**
- `test-suite/` extracted files: **1**

## Gaps / notes

- `w3c/vc-di-eddsa-test-suite` carries **no static interop fixtures** (no
  pre-signed documents, no expected proofs, no key files) — credentials are
  generated live against registered implementation endpoints, and the suite's
  `reports/` directory holds no vector data. The only vendorable static input was
  `validVc.js` (vendored as `test-suite/valid-vc.json`). Interop coverage for AC-1
  therefore rests on the spec vectors above plus locally constructed fixtures.
- The spec's test vectors define **no negative cases** (tampered document, wrong
  key, mismatched `proofPurpose`); AC-1's negative cases must be constructed
  locally (see `tests/fixtures/constructed/`).
