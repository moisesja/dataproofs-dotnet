# PROVENANCE — tests/fixtures/w3c/vc-di-bbs/

Test fixtures for the `bbs-2023` Data Integrity cryptosuite (PRD FR-12, AC-1).

## Sources

### 1. Specification: W3C Data Integrity BBS Cryptosuites v1.0

- **Document:** Data Integrity BBS Cryptosuites v1.0 — *W3C Candidate
  Recommendation Draft, 07 April 2026*
- **Fetched URL:** `https://www.w3.org/TR/vc-di-bbs/` (retrieved 2026-06-11)
- **"This version" URL of the retrieved page:**
  `https://www.w3.org/TR/2026/CRD-vc-di-bbs-20260407/`
- **Snapshot used:** CRD 2026-04-07 — the live `/TR/vc-di-bbs/` page *is* the
  CRD snapshot pinned by the PRD (§12.3, decision 3, "CRD snapshot 2026-04-07").
  The spec has **not** advanced past the pin; no dated-URL fallback was needed.
- **SHA-256 of retrieved HTML:**
  `707961d845e947a4ffab06db51d3f5163e562c4e6f92603c0c0ec95e5e2486be`

### 2. Repository: w3c/vc-di-bbs

- **Origin URL:** `https://github.com/w3c/vc-di-bbs`
- **Commit SHA (HEAD at retrieval):** `d1036535bc9da24919548831db3ddd487dfce83f`
  (committed 2026-04-07 — same day as the CRD publication)
- **Retrieval:** shallow clone (`git clone --depth 1`), 2026-06-11

## Contents

### `TestVectors/` — verbatim copy of the repository's `TestVectors/` tree

**No local transformation applied** — byte-identical copy (verified with
`diff -r` against the clone). These files are the *source* of the worked
test-vector examples embedded in the spec: the spec's `index.html` includes
them via ReSpec `data-include`, so they are already the clean machine-readable
form of the spec-embedded examples. Cross-checks performed on 2026-06-11
against the published CRD HTML confirmed exact content matches for:

- base `proofValue` (`addSignedSDBase.json`),
- derived `proofValue` (`derivedRevealDocument.json`),
- `proofHash` (`addHashData.json`).

Role map for the core `bbs-2023` worked vectors (directory root = core suite;
spec §A.1–A.2):

| Role | File(s) |
| --- | --- |
| Unsigned input document | `windDoc.json` |
| Key material (BLS12-381 G2 public/private key, hex) + HMAC key | `BBSKeyMaterial.json` (`publicKeyHex`, `privateKeyHex`, `hmacKeyString`) |
| Derive-time material (presentation header, pseudo-random seed) | `BBSDeriveMaterial.json` |
| Mandatory pointers | `windMandatory.json` |
| Selective pointers | `windSelective.json` |
| Pointer → value resolution | `addPointerValues.json` |
| Base proof components: canonical doc | `addBaseDocCanon.json` |
| Base proof components: HMAC-relabeled canonical doc | `addBaseDocHMACCanon.json` |
| Base proof components: transformed doc (group partition) | `addBaseTransform.json` |
| Base proof components: proof config + canonical form | `addProofConfig.json`, `addProofConfigCanon.txt` |
| Base proof components: hash data (`proofHash`, `mandatoryHash`) | `addHashData.json` |
| Base proof components: raw BBS signature + inputs | `addRawBaseSignatureInfo.json` |
| **Expected base proof (CBOR `proofValue`, tag `0xd95d02`, multibase prefix `u2V0C`)** | `addSignedSDBase.json` |
| Derived proof intermediates (indexes, disclosure/group data, recovered base) | `derivedAdjIndexes.json`, `derivedGroupIndexes.json`, `derivedDisclosureData.json`, `derivedRecoveredBaseData.json` |
| Derived (reveal) document, unsigned | `derivedUnsignedReveal.json` |
| **Expected derived proof (CBOR `proofValue`, tag `0xd95d03`, multibase prefix `u2V0D`)** | `derivedRevealDocument.json` |
| Verifier-side parsed `proofValue` + N-Quads | `verifyDerivedProofValue.json` *(in feature subdirs)*, `verifyNQuads.json` *(in feature subdirs)* |
| Pre-signed credential examples (mandatory-only / selective) | `prCredUnsigned.json`, `prCredMandatory.json`, `prCredSelective.json` |

Optional-feature vector sets (same file naming scheme per directory; spec
§3 optional features and their test-vector appendices):

- `FeatureInputs/` — shared inputs for the feature vectors (license document,
  pointers, `holderSecret`, `proverNym`, `signerNymEntropy`, `verifierInfo`).
- `HolderBinding/` — holder-binding (commitment) vectors; CBOR `proofValue`
  headers `u2V0E` (base, tag `0xd95d04`) / `u2V0F` (derived, tag `0xd95d05`).
- `Pseudonym/` — pseudonym vectors; headers `u2V0I` (base, tag `0xd95d08`) /
  `u2V0J` (derived, tag `0xd95d09`).
- `PseudonymHB/` — pseudonym + holder-binding combined; same header tags as
  `Pseudonym/` at this snapshot.
- `prc/` — per-claim (license) credential run of the core suite; headers
  `u2V0C` / `u2V0D`.

Key-material cross-check (performed 2026-06-11, recorded here, no file
modified): the worked vectors' `verificationMethod`
(`did:key:zUC7Derd…` in `addProofConfig.json`) base58-decodes to multicodec
prefix `0xeb01` (BLS12-381 G2) followed by exactly the 96-byte
`publicKeyHex` of `BBSKeyMaterial.json`.

### `spec-examples/` — examples extracted from the published CRD HTML

These six examples appear **inline** in the spec (not backed by `TestVectors/`
files). Extracted from the retrieved
`https://www.w3.org/TR/2026/CRD-vc-di-bbs-20260407/` HTML on 2026-06-11.

| File | Spec example |
| --- | --- |
| `bls12-381-g2-public-key-multikey.json` | Example 1: "A BLS12-381 G2 group public key, encoded as a Multikey" |
| `bls12-381-g2-public-key-controller-document.json` | Example 2: "… encoded as a Multikey in a controller document" |
| `blank-node-stability-vc-original.json` | "A VC for a set of windsurfing sails" (§ on blank-node label stability / HMAC motivation) |
| `blank-node-stability-vc-original-canonical.txt` | "Canonical form of the VC for a set of windsurfing sails" (RDFC-1.0 N-Quads) |
| `blank-node-stability-vc-updated.json` | "A VC for a slightly updated set of windsurfing sails" |
| `blank-node-stability-vc-updated-canonical.txt` | "Canonical form of the updated VC for a set of windsurfing sails" (RDFC-1.0 N-Quads) |

**Local transformations applied (extraction from spec HTML):**

1. Stripped HTML tags and unescaped HTML entities from the `<pre>` example
   bodies.
2. `bls12-381-g2-public-key-*.json`: rejoined the `publicKeyMultibase` string,
   which the spec HTML hard-wraps across lines with indentation (newline +
   leading spaces removed *inside the quoted string only*); JSON re-serialized
   with 2-space indentation. Sanity check: the rejoined value base58-decodes to
   multicodec prefix `0xeb01` + 96 bytes, as required for BLS12-381 G2.
3. `blank-node-stability-vc-*.json`: removed the spec's two ` // …`
   prose annotation comments (which make the example non-JSON); JSON
   re-serialized with 2-space indentation.
4. `.txt` files (N-Quads): verbatim text after tag-strip/unescape, plus a
   trailing newline.

**Note:** the Multikey in Examples 1–2 (`zUC7EK3Z…`, `https://example.com/issuer/123`)
is an *illustrative* key and is **not** the key used by the `TestVectors/`
worked vectors (`did:key:zUC7Derd…`). Both decode with the `0xeb01`
BLS12-381-G2 multicodec prefix.

## Fixture counts (recorded per the AC-2 count-assertion convention)

| Directory | Files |
| --- | --- |
| `TestVectors/` (root) | 23 |
| `TestVectors/FeatureInputs/` | 7 |
| `TestVectors/HolderBinding/` | 18 |
| `TestVectors/Pseudonym/` | 19 |
| `TestVectors/PseudonymHB/` | 19 |
| `TestVectors/prc/` | 18 |
| **`TestVectors/` total** | **104** |
| `spec-examples/` | 6 |
| **Fixture files total** (excluding this PROVENANCE.md) | **110** |

All 103 `.json` fixture files parse as valid JSON (verified 2026-06-11);
the remaining 7 fixture files are `.txt` (5 × `addProofConfigCanon.txt`
N-Quads, 2 × blank-node-stability canonical N-Quads).

## Retrieval date

2026-06-11
