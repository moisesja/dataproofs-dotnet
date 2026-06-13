# Provenance — constructed controller-authorization fixtures (AC-1 step 5)

These fixtures are **locally constructed** (not vendored): the W3C vc-di-eddsa /
vc-di-ecdsa vector sets define no controller-authorization negative cases (see
`tests/fixtures/w3c/vc-di-eddsa/PROVENANCE.md`, "Gaps"), so AC-1 step 5 requires a
provenance-tracked constructed set per PRD §9.

- Created: **2026-06-12**, in-repo, by the Phase A coding agent.
- Generator: a throwaway console program referencing
  `src/DataProofsDotnet.Core` (repo state: commit `91cf139` plus the Phase A
  fixes landed with these fixtures), using the library's own
  `DataIntegrityProofPipeline` with the deterministic `eddsa-jcs-2022` suite
  (Ed25519 signing is deterministic, so all signed fixtures are byte-reproducible
  from the inputs recorded here).
- Cryptography: NetCrypto `1.0.0-preview.1` (`DefaultKeyGenerator.FromPrivateKey`,
  `KeyPairSigner`); Multikey encoding via NetCid `1.6.0`.
- Generation-time sanity gates: `signed-assertion.json` and
  `signed-unauthorized.json` verified against their own keys (raw-key path), and
  `signed-assertion.json` was checked to FAIL against key B, before files were
  written. The test suite re-verifies all of this independently.

## Key material (fully deterministic)

| Key | Ed25519 seed (hex) | publicKeyMultibase | verification method id |
|---|---|---|---|
| key-a | `01` × 32 | see `keys.json` | `did:example:controller-alpha#key-a` |
| key-b | `02` × 32 | see `keys.json` | `did:example:controller-alpha#key-b` |

`keys.json` records the seeds and the derived `publicKeyMultibase` values.

## Files

| File | Content |
|---|---|
| `unsigned-credential.json` | Minimal VCDM 2.0 credential used as the signing input (pretty-printed) |
| `controller-document.json` | Controller document for `did:example:controller-alpha`: lists **key-a under `assertionMethod` and `authentication`**, **key-b under `authentication` only** |
| `controller-document-rogue.json` | Same `key-a` method but its `controller` property names `did:example:mallory` — the claimed controller does **not** control the method (AC-1 step 5c input) |
| `signed-assertion.json` | Credential signed by key-a, `proofPurpose: assertionMethod` — authorized; verifies (step 5a) |
| `signed-unauthorized.json` | Credential signed by key-b, `proofPurpose: assertionMethod` — the **signature is valid** but key-b is not listed under `assertionMethod`; must fail with `INVALID_VERIFICATION_METHOD` on the resolver path (step 5b) and verify on the raw-key path (step 5d) |
| `keys.json` | Seeds + multikeys for both keys |

Signed documents are stored in the exact compact serialization
(`DataProofsJsonOptions.Default`) the pipeline emits, plus a trailing newline,
so byte comparisons against pipeline output are exact after trimming the
trailing newline.

## Local transformations

None — all files were emitted directly by the generator described above.
