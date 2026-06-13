# Provenance — constructed proof-set / proof-chain fixtures (AC-1 step 6)

These fixtures are **locally constructed** (not vendored): the W3C vc-di-eddsa
`TestVectors/proof-set-chain/` vectors use `eddsa-rdfc-2022` (the RDFC family,
Phase E / `DataProofsDotnet.Rdfc`), so the JCS-suite set/chain coverage that
Phase A's AC-1 step 6 requires is provided by this constructed set using the
deterministic `eddsa-jcs-2022` suite.

- Created: **2026-06-12**, in-repo, by the Phase A coding agent.
- Generator: a throwaway console program referencing
  `src/DataProofsDotnet.Core` (repo state: commit `91cf139` plus the Phase A
  fixes landed with these fixtures), using `DataIntegrityProofPipeline.AddProofAsync`
  with `eddsa-jcs-2022` (deterministic Ed25519 signatures ⇒ byte-reproducible).
- Cryptography: NetCrypto `1.0.0-preview.1`; Multikey via NetCid `1.6.0`.
- Generation-time sanity gates: `signed-set-2.json` and `signed-chain-2.json`
  verified through the resolver path; `chain-missing-previous.json` and
  `chain-out-of-order.json` checked to FAIL — before files were written. The
  chain shape (full previous proofs embedded as an **array** in the signing
  input) mirrors the W3C worked example
  `tests/fixtures/w3c/vc-di-eddsa/TestVectors/proof-set-chain/proofChainTempDoc2.json`.

## Key material (fully deterministic)

| Key | Ed25519 seed (hex) | verification method id |
|---|---|---|
| key-1 | `11` × 32 | `did:example:signer-1#key-1` |
| key-2 | `12` × 32 | `did:example:signer-2#key-2` |

`keys.json` records the seeds and derived `publicKeyMultibase` values.

## Files

| File | Content |
|---|---|
| `unsigned.json` | Base credential (pretty-printed) |
| `set-proof-1-options.json` / `set-proof-2-options.json` | Proof options for the two independent set proofs (no `id`, no `previousProof`) |
| `signed-set-1.json` | `unsigned.json` + proof 1 (key-1) — single proof, object form |
| `signed-set-2.json` | `signed-set-1.json` + proof 2 (key-2) — **expected byte output** of adding the second set proof (two-element `proof` array) |
| `chain-proof-1-options.json` / `chain-proof-2-options.json` | Chain proof options; proof 1 carries `id` `urn:uuid:b3b09d11-…`; proof 2 carries `id` `urn:uuid:f4ad9b3e-…` and `previousProof` referencing proof 1 |
| `signed-chain-1.json` | `unsigned.json` + chain proof 1 |
| `signed-chain-2.json` | `signed-chain-1.json` + chain proof 2 — **expected byte output** of adding the chained proof (proof 2 signed over the document with proof 1 embedded as a one-element array) |
| `chain-missing-previous.json` | `signed-chain-2.json` with proof 1 **removed**: proof 2's `previousProof` is dangling → must fail with `PROOF_VERIFICATION_ERROR` (step 6c, "missing") |
| `chain-out-of-order.json` | `signed-chain-2.json` with the two proofs' `id` values **swapped**: the dependency reference resolves to bytes that were never the signed dependency → must fail with `PROOF_VERIFICATION_ERROR` (step 6c, "out of order") |
| `keys.json` | Seeds + multikeys for both keys |

Signed documents are stored in the exact compact serialization
(`DataProofsJsonOptions.Default`) the pipeline emits, plus a trailing newline,
so byte comparisons against pipeline output are exact after trimming the
trailing newline.

## Local transformations

The two negative files were derived from `signed-chain-2.json` by JSON-node
edits (remove array element 0; swap the two `id` member values) and re-emitted
in the same compact serialization. No other transformations.
