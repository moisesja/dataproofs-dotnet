# Phase E — DataProofsDotnet.Rdfc (FR-9..12, AC-1 RDFC/BBS, AC-2)

Worktree branch: worktree-agent-a210cd0881ebca44b

## Plan

### FR-9 — RDFC-1.0 canonicalizer (public interface, no dotNetRDF/Newtonsoft in signatures)
- [ ] `IRdfCanonicalizer` — public interface: canonicalize a JSON-LD document (JsonElement) and raw N-Quads (string) to canonical N-Quads bytes/string, hash-algorithm selectable.
- [ ] `RdfCanonicalizationException` — public wrapper exception (maps dotNetRDF/JSON-LD failures).
- [ ] `RdfcDocumentCanonicalizer` — dotNetRDF impl (JsonLdParser + RdfCanonicalizer). Takes IDocumentLoader. Hash algo param (SHA256 default, SHA384 for P-384). Keep dotNetRDF/Newtonsoft strictly internal.

### FR-10 — Document loader
- [ ] `IDocumentLoader` — public interface (Uri -> loaded context document). No Newtonsoft/dotNetRDF type in signature; return a small public LoadedDocument record (string contents + url).
- [ ] `OfflineDocumentLoader` (DEFAULT) — embedded contexts, fail-closed. Embed credentials-v2, credentials/examples/v2, data-integrity-v2, data-integrity-v1, multikey-v1, bbs-v1, credentials-v1, jws-2020-v1 as resources.
- [ ] `CachingNetworkDocumentLoader` — opt-in, plain Dictionary cache (no Caching package), never default.
- [ ] Internal adapter bridging IDocumentLoader -> dotNetRDF JsonLdProcessorOptions.DocumentLoader (JToken).

### FR-11 — RDFC suites
- [ ] `RdfcCryptosuite` internal base (mirrors Core JcsCryptosuite, but RDFC canonicalization). hashData = hash(canonProofConfig) ‖ hash(canonDocument). proofConfig uses proof's @context.
- [ ] `EddsaRdfc2022Cryptosuite` (Ed25519, SHA-256, deterministic).
- [ ] `EcdsaRdfc2019Cryptosuite` (P-256/SHA-256, P-384/SHA-384, P1363).
- [ ] `RdfcCryptosuiteRegistration` — extension to register RDFC suites + bbs-2023 into a CryptosuiteRegistry.

### FR-12 — bbs-2023
- [ ] JSON-pointer (RFC 6901) document selection (`selectJsonLd` group partition).
- [ ] RDFC + HMAC blank-node relabel (sorted HMAC of c14n labels).
- [ ] Base proof: canonicalize, hmac-relabel, partition mandatory/non-mandatory, proofConfig hash, mandatory hash, BBS sign non-mandatory msgs (with mandatoryHash-derived header), CBOR base proofValue (tag 0xd95d02, `u` multibase).
- [ ] Derived proof (holder): select disclosure, derive BBS proof over revealed indices, CBOR derived proofValue (tag 0xd95d03).
- [ ] Derived verify (verifier): parse CBOR, recover, verify BBS proof.
- [ ] BBS-absent: registration succeeds, use throws BbsUnavailableException.

### Tests
- [ ] AC-2: manifest-driven theory over rdf-canon (86 entries, count assert, negative case 074c).
- [ ] AC-1 1-3 RDFC: verify-direction for vc-di-eddsa/ecdsa rdfc vectors + byte-identical eddsa-rdfc-2022 proofValue + ecdsa round-trip + canonical/hashData byte-equal.
- [ ] AC-1 4 bbs: base->derive->verify per fixture pointers; own base; mandatory violation rejected.
- [ ] Unit: offline loader serves/fails-closed; caching loader not default; canonicalizer error mapping.

### Verify
- [ ] build /warnaserror clean; dotnet test green (BBS live on osx-arm64).
- [ ] PublicAPI.Unshipped.txt in sync.

## Notes
- BBS pin re-verified: PROVENANCE confirms CRD 2026-04-07 (commit d1036535), not advanced. OK.
- BBS native libzkryptium present for osx-arm64 -> BBS runs LIVE.
- credentials/examples/v2 context NOT vendored -> must vendor + embed for AlumniCredential vectors.
- Stale NetCid 1.6.0 cache could not be purged (perm denied); avoid maxOutputBytes overloads OR they exist anyway. Core built fine.
</content>
