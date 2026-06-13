# Provenance — embedded JSON-LD contexts (DataProofsDotnet.Rdfc)

These are the version-pinned, provenance-tracked W3C JSON-LD contexts the offline
document loader (`OfflineDocumentLoader`, FR-10) serves as embedded assembly resources.
The loader fails closed on any context outside this set.

## Vendored W3C contexts (embedded from the provenance source of record)

The seven core contexts are embedded **directly from** the repository's single
provenance-tracked source directory, `tests/fixtures/contexts/`, via `<EmbeddedResource>`
items in `DataProofsDotnet.Rdfc.csproj` (with stable logical names). Their full origin,
retrieval method, git pins, and SHA-256 hashes are recorded in
`tests/fixtures/contexts/PROVENANCE.md`. Embedding from that one source guarantees the
package's served bytes are byte-identical to the provenance record (no drift):

| Logical name (context URL → embedded under) | Source file |
| --- | --- |
| `https://www.w3.org/ns/credentials/v2` | `credentials-v2.jsonld` |
| `https://www.w3.org/2018/credentials/v1` | `credentials-v1.jsonld` |
| `https://w3id.org/security/data-integrity/v2` | `data-integrity-v2.jsonld` |
| `https://w3id.org/security/data-integrity/v1` | `data-integrity-v1.jsonld` |
| `https://w3id.org/security/multikey/v1` | `multikey-v1.jsonld` |
| `https://w3id.org/security/bbs/v1` | `bbs-v1.jsonld` |
| `https://w3id.org/security/suites/jws-2020/v1` | `jws-2020-v1.jsonld` |

## Locally authored context

| File | Context URL | Notes |
| --- | --- | --- |
| `credentials-examples-v2.jsonld` | `https://www.w3.org/ns/credentials/examples/v2` | The W3C credentials examples v2 context. The upstream document is a single `@vocab` mapping to `https://www.w3.org/ns/credentials/examples#`; reconstructed here byte-minimal because the upstream copy is not vendored under `tests/fixtures/contexts/`. Required to canonicalize the AlumniCredential worked vectors of `vc-di-eddsa`/`vc-di-ecdsa` (their `alumniOf`/`AlumniCredential` terms expand under this `@vocab`). Verified: re-canonicalizing the AlumniCredential vectors with this context reproduces the spec's expected canonical N-Quads (`examples#alumniOf`, `examples#AlumniCredential`) byte-for-byte and the spec's `docHash`. |

## bbs-2023 note

`bbs-2023` (CRD 2026-04-07) defines no dedicated context: its examples use only
`credentials/v2`, `data-integrity/v2`, and `multikey/v1` (all above). `bbs-v1.jsonld`
is the legacy BBS+ LD-signatures context, kept only because the URL resolves; it is not
required by `bbs-2023`.
