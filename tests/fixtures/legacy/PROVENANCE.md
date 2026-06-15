# Legacy Linked-Data-Signature golden vectors — provenance

These fixtures are **cross-stack interop golden vectors**: they were produced by
**zcap-dotnet** (a separate, independent implementation of the 2020-era Linked-Data-Signature
wire convention) and are vendored here verbatim so the DataProofsDotnet.Legacy suites can be
proven byte-compatible with proofs zcap actually issues. The whole point of these fixtures is
that they are NOT produced by the code under test.

## `zcap/ed25519-signature-2020-delegated.json`

- **Origin (known-answer test):** `zcap-dotnet` repository,
  `tests/ZcapLd.Core.Tests/Compliance/ProofGoldenVectorTests.cs`
  (test `DelegatedCapability_DeterministicProofValue_MatchesGolden`).
- **Securing mechanism:** `Ed25519Signature2020` — a legacy embedded Linked-Data-Signature.
  The signing input is `JCS(document-with-the-proof-(minus proofValue)-re-nested)` fed
  directly to Ed25519 (the primitive hashes internally; there is no explicit pre-hash). The
  proof carries `type:"Ed25519Signature2020"` and **no `cryptosuite`** member.
- **Signing key (TEST ONLY, never a real key):** Ed25519 seed = the bytes `01 02 … 20`
  (i.e. `Enumerable.Range(1, 32)` cast to bytes 1..32).
- **Derived public key (multikey / did:key):**
  `z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7`
  (zcap asserts `KeyPair.MultibasePublicKey` equals this for the fixed seed).
- **`created`:** `2026-06-13T00:00:00.000000Z` (verbatim wire string).
- **Expected `proofValue`:**
  `z5vKNNJVDziWyjoSSxFCNXJ6ZL4FSfrA7TbWDwhkBmkHCgN4448kTMJTUoK3pW35dNrGbyWP1moBSCb4nsYAc5fx8`
  (base58-btc multibase of the raw 64-byte Ed25519 signature).

Ed25519 is deterministic (RFC 8032), so this `proofValue` is byte-reproducible: a DataProofs
test re-derives the same key from the seed, signs the same JCS input, and asserts the produced
`proofValue` equals zcap's. It also loads the fixture and verifies zcap's `proofValue` through
the DataProofs pipeline using only the public key embedded in `verificationMethod`.

## P-256 (`EcdsaSecp256r1Signature2019`)

zcap-dotnet ships **no** standalone P-256 signed-capability vector — P-256 appears only in its
unit/integration crypto tests, never as a signed LD-Signature. P-256 ECDSA signing is also
non-deterministic (random `k`), so a freshly created `proofValue` is not byte-reproducible.
The DataProofs P-256 coverage is therefore round-trip (create → verify) plus a verify-only
self-signed vector (verification is deterministic even though signing is not); it never asserts
a fixed P-256 `proofValue` across runs.
