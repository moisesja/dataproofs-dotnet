# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-11-20

**This is a minor release.** The public API only adds, in `DataProofsDotnet.Jose` and `DataProofsDotnet.Rdfc`:
nothing is removed or changed, and one constant, `SdJwtVcConstants.TransitionalMediaType`, is marked `[Obsolete]`. For input that 2.0.0
issued, every issuer emits the same bytes. **It refuses some credentials that 2.0.0 verified, including some this
library issued.** Read these entries before upgrading:

- an SD-JWT or SD-JWT VC whose `exp` has passed or whose `nbf` is still ahead, or whose `nbf` or `exp` is not a
  number or lies outside -62135596800 to 253402300799 seconds (0001-01-01T00:00:00Z to 9999-12-31T23:59:59Z),
  and a Key Binding JWT whose own `nbf` or `exp` fails the same way (*Fixed*, issue #45);
- an SD-JWT VC with `typ: vc+sd-jwt`, or with an `aka_vcts` that is disclosed or malformed (*Changed*, issue #49);
- an SD-JWT VC with Disclosures or decoy digests inside a reserved claim such as `status` or `cnf` (*Fixed*, issue
  #48);
- an SD-JWT with a digest repeated anywhere in the payload, an `_sd_alg` below the top level, or a Disclosure
  named `_sd_alg` (*Fixed*, issue #48).

The SD-JWT issuers also refuse to sign several of these shapes, and each entry says which. A consumer that
references `System.Formats.Cbor` directly below 10.0.15 must raise that reference (*Security*, issue #50). The
reasons this is a minor are under *Why this is a minor and not a major*, at the end of this section.

### Security

- **`System.Formats.Cbor` lifted 10.0.8 → 10.0.15**
  ([GHSA-vmv3-wvjp-wqpj](https://github.com/advisories/GHSA-vmv3-wvjp-wqpj), CVE-2026-118747, a .NET
  denial of service: colliding CBOR map keys can hash-flood its map-key uniqueness checks; affected
  `>= 10.0.0, < 10.0.15`, published 2026-11-10). `DataProofsDotnet.Cose` (COSE_Sign1, CWT) and
  `DataProofsDotnet.Rdfc` (the bbs-2023 `proofValue`) reference it directly, and
  `DataProofsDotnet.Legacy` and `DataProofsDotnet.Extensions.DependencyInjection` carry it through
  them. Every published version of Cose and Rdfc, 0.1.0-preview.1 through 2.0.0, declares 10.0.8, so a
  consumer of any of the four that treats warnings as errors fails restore with `NU1902` ([#50](https://github.com/moisesja/dataproofs-dotnet/issues/50)). The packages now
  declare `System.Formats.Cbor` `>= 10.0.15`. No code in this library changes, nor its public API or
  the bytes it emits, and the COSE and bbs-2023 suites, vectors included, pass unchanged on 10.0.15.
  Upgrade to this release. Until then, a direct
  `<PackageReference Include="System.Formats.Cbor" Version="10.0.15" />` in the consuming project
  lifts the transitive version and clears the audit for all four packages. A consumer that already
  references `System.Formats.Cbor` directly at 10.0.8 to 10.0.14 gets `NU1605` (a package downgrade,
  which the .NET SDK treats as an error by default) once it moves to this release: raise that
  reference to 10.0.15 or remove it.

### Changed

- **SD-JWT VC is re-pinned from `draft-ietf-oauth-sd-jwt-vc-16` to `-27`** (issue
  [#49](https://github.com/moisesja/dataproofs-dotnet/issues/49)). -27, of 2026-11-16, is in IESG
  Evaluation, the last stage before RFC publication. Error messages and XML docs now cite -27 and its
  section numbers; the ones they cited before (§3.5, §3.2.2.2, §3.2.2.1.1) matched neither -16 nor -27.
  The `VC_*` codes that start each message are unchanged; a consumer matching the rest of the text will
  see it change. The vendored examples moved to `tests/fixtures/ietf/sd-jwt-vc-27/`: -27 re-signed every
  example, and the library verifies all of them. The steps for the next move, to the RFC, are in PRD
  §12.2. The behaviour changes follow.

- **`SdJwtVcVerifier` no longer accepts `typ: vc+sd-jwt`. This narrows what it accepts.** -16 asked
  Verifiers to accept the former `vc+sd-jwt` as well as `dc+sd-jwt` "for a reasonable transitional
  period"; -19 removed that sentence, and -27 §2.2.1 says "The typ value MUST use dc+sd-jwt". An SD-JWT
  whose issuer-JWT `typ` is anything other than exactly `dc+sd-jwt` now fails with
  `VC_MEDIA_TYPE_INVALID` before its signature is checked. There is no opt-in. W3C VC-JOSE-COSE uses
  `vc+sd-jwt` for a different format, a VCDM payload with no `vct`, and an alias, even one behind a
  flag, would keep the two confusable inside the profile verifier.
  - *This library's own output:* `SdJwtVcIssuer` has set `typ: dc+sd-jwt` in every release from
    0.1.0-preview.1 to 2.0.0, so no SD-JWT VC it issued is affected. A token built with the generic
    `SdJwtIssuer` and an explicit `typ: "vc+sd-jwt"`, as the 2.0.0 SD-JWT VC sample did with
    `SdJwtVcConstants.TransitionalMediaType`, is now refused.
  - *What to do:* issue SD-JWT VCs with `SdJwtVcIssuer`, or with `typ: dc+sd-jwt`. A verifier still
    receiving `vc+sd-jwt` SD-JWT VCs from an issuer on a pre-November-2024 draft needs that issuer to
    reissue them. A verifier receiving W3C VC-JOSE-COSE `vc+sd-jwt` credentials should not route them
    here: they failed with `VC_VCT_MISSING` before and fail with `VC_MEDIA_TYPE_INVALID` now. The
    generic `SdJwtVerifier` does not check `typ` (RFC 9901 §9.11 leaves explicit typing to the profile)
    and is the layer to build that format on.
  - `SdJwtVcConstants.TransitionalMediaType` keeps its value and is marked `[Obsolete]`. Using it raises
    warning CS0618, which a build that treats warnings as errors reports as an error. There is no
    replacement constant: code that names the W3C VC-JOSE-COSE `vc+sd-jwt` media type, for example to
    route such credentials away from `SdJwtVcVerifier`, writes the literal. Already-compiled code is
    unaffected, because the compiler copies a constant's value into the code that uses it.

- **`aka_vcts` is a registered SD-JWT VC claim** (-18; -27 §2.2.2.2 and §2.2.2.3). Under -16 it was an
  ordinary claim that could take any value and be selectively disclosed, so both rules below refuse
  input that was valid then, including credentials `SdJwtVcIssuer` 2.0.0 would have issued:
  - it is on `SdJwtVcConstants.MustNotBeSelectivelyDisclosed`, so `SdJwtVcIssuer` throws
    `MalformedJoseException` for a `DisclosureFrame` entry keyed `aka_vcts`, whole claim or elements.
    `SdJwtVcVerifier` enforces the rule by position and fails with `VC_DISALLOWED_DISCLOSURE` when the
    top-level `aka_vcts` comes from a Disclosure, or when its signed value holds any disclosure site (an
    `{"...": digest}` element placeholder or an `_sd` array) whether the holder presents the Disclosure,
    withholds it, or none exists. A claim named `aka_vcts` nested inside another claim, such as
    `related.aka_vcts`, is an ordinary claim: it may be selectively disclosed and is not held to the
    format below. The same positional rule now covers the other seven names (see *Fixed*, issue
    [#48](https://github.com/moisesja/dataproofs-dotnet/issues/48));
  - when present it must be a non-empty array of non-empty strings that does not contain the `vct`
    value. `SdJwtVcIssuer` throws `MalformedJoseException` otherwise, and `SdJwtVcVerifier` checks the
    value the issuer signed, so withholding an element cannot make a malformed array pass, and fails
    with the new code `VC_AKA_VCTS_INVALID`.

  *What to do:* issuers put `aka_vcts` in the clear, as an array of the further types. Verifiers that
  match a credential's type use `vct` and the `aka_vcts` values, and only those: -27 says Type Metadata
  and `extends` do not add types.

- **`SdJwtVcIssuer` refuses a `vct` or `aka_vcts` value that is not well-formed UTF-16.** A lone surrogate
  in a caller-built claims set was signed as U+FFFD, so the adversarial review could issue an `aka_vcts`
  that differed from `vct` before signing and equalled it after, which the verifier then refused. Such a
  value now throws `MalformedJoseException`, as does a claims set parsed from JSON that escapes a lone
  surrogate in either claim, which threw `InvalidOperationException` before. Values decoded from the
  wire cannot carry one, so verification is unchanged.

### Added

- **`SdJwtVcConstants.AkaVctsClaim`** (`"aka_vcts"`).
- **Documentation for what the SD-JWT VC verifier leaves to the caller:** `ITypeMetadataResolver` lists
  the -27 retrieval rules an HTTP-backed resolver must carry (https only, redirects, time and size
  bounds, server-side request forgery checks on every URL, the `vct` identity check and `vct#integrity`);
  `SdJwtVcVerificationResult.TypeMetadata` says the document is returned unprocessed (-27 §5.7);
  `SdJwtVcConstants.StatusClaim` and the verifier say `status` is carried, not checked; `SdJwtVerifier`
  says it does not check `typ`.
- **SD-JWT VC Type Metadata processing** (issue [#47](https://github.com/moisesja/dataproofs-dotnet/issues/47);
  -27 §5, §6, §7.4; PRD FR-17a). Until now the verifier handed back whatever document the resolver returned
  and checked nothing in it. Two new entry points process it fully, as -27 §5.7 requires before the contents
  are used: `SdJwtVcVerifier.VerifyWithTypeMetadataAsync` and `SdJwtVcIssuer.IssueWithTypeMetadataAsync`, both
  taking `TypeMetadataProcessingOptions`. Once requested, processing is required: a credential whose metadata
  cannot be retrieved or processed is refused.
  - *Retrieval.* A new `ITypeMetadataDocumentResolver` returns the octets of a document (integrity is over the
    octets, which a parsed `JsonObject` cannot give back), called for the `vct` and each `extends` value, only
    after the issuer signature verified. `LocalCacheTypeMetadataDocumentResolver` is the offline default; the
    library never fetches anything. A resolver that returns `null` gives `VC_TYPE_METADATA_UNAVAILABLE`, a
    verdict. One that throws gives `VC_TYPE_METADATA_RESOLVER_FAULT` with the exception on the new
    `SdJwtVcVerificationResult.TypeMetadataResolverFault`, a fault the caller can retry; at issuance it is a
    `JoseException` (not a `MalformedJoseException`) with the resolver's exception inside.
  - *Checks, each with a stable code.* `vct#integrity` and every `extends#integrity` against the octets, before
    parsing (`VC_TYPE_METADATA_INTEGRITY_INVALID` for a malformed value or no supported algorithm,
    `VC_TYPE_METADATA_INTEGRITY_MISMATCH`; sha256/384/512, the strongest present decides); each document's
    `vct` identical to the reference, no normalization (`VC_TYPE_METADATA_VCT_MISMATCH`); the document's shape
    and size (`VC_TYPE_METADATA_INVALID`); `extends` cycles and chains longer than `MaxExtendsDepth`, default 8
    (`VC_TYPE_METADATA_EXTENDS_CYCLE`, `VC_TYPE_METADATA_EXTENDS_DEPTH`); malformed `claims`, `path`,
    `mandatory` or `sd`, or a path twice in one document (`VC_CLAIM_METADATA_INVALID`); a child changing `sd`
    away from `always`/`never` or making a mandatory claim optional (`VC_CLAIM_METADATA_OVERRIDE_INVALID`);
    and the credential against the merged claim metadata (`VC_CLAIM_PATH_INVALID`, `VC_CLAIM_SD_VIOLATION`,
    `VC_CLAIM_MANDATORY_MISSING`). Malformed display, rendering or `svg_id` never reject (-21).
  - *Judged on the credential as issued.* A claim is selectively disclosable when a Disclosure supplies it
    directly; array positions count undisclosed elements. A withheld selectively disclosable claim is not a
    missing mandatory one; a mandatory claim is missing only where nothing could hide it. Two consequences to
    know: a verifier cannot tell a withheld `sd: never` member from a decoy, so it is detected only when the
    claim is also mandatory; and an issuer that adds decoys to arrays shifts the positions -27 counts.
  - *Resource bounds, beyond the two options.* An `extends` chain may hold at most 10,000 claim, path, display and
    template entries, counted in every document of the chain; past that it fails with `VC_TYPE_METADATA_INVALID`.
    A display or template element without its required string members (`locale` and `name`, `locale` and `label`,
    `uri`) is skipped and not counted, so a malformed display still never rejects.
    Validation against one credential may spend at most 1,000,000 units of work, charged before the work. A path
    step costs one unit; a key lookup costs one unit per 32 characters of its key. Past that it fails with
    `VC_CLAIM_METADATA_INVALID`. Both are fixed limits: a rich real type holds a few thousand entries. The result
    keeps the documents as octets and parses them again on each access, and an error message repeats at most 120
    characters of a value.
  - *Issuance is checked by the same code:* the verifier's processing runs on the issued credential with every
    Disclosure, knowing every unresolved digest is a decoy, and the credential is not returned when it fails. It
    refuses whatever that verification refuses, and also a mandatory claim that only a decoy stands in for.
  - *The processed metadata is typed* on `SdJwtVcVerificationResult.ProcessedTypeMetadata`: merged claim
    metadata (`ClaimMetadata`, `ClaimPathComponent`, `ClaimDisplayMetadata`, `ClaimSelectiveDisclosure`) and the
    effective display with rendering (`TypeDisplayMetadata`, `TypeRenderingMetadata`, `SimpleRenderingMetadata`,
    `RenderingImageMetadata`, `SvgTemplateMetadata`), plus the parsed documents. `TypeMetadataIntegrity.Matches`
    and `Compute` give a wallet the same check for `uri#integrity` on a logo or template it fetches, and an
    issuer the value to put in `vct#integrity`.

  Type Metadata processing changes nothing for existing callers: `VerifyAsync`, `IssueAsync` and the raw
  `ITypeMetadataResolver` path do not process it, and no member was removed or changed. (The same methods
  change in this release for other reasons: see issues #45, #48 and #49 in this section and under *Changed*
  and *Fixed*.) A verifier that wants processing moves to
  `VerifyWithTypeMetadataAsync` and supplies document octets; the credentials it then refuses are ones that
  contradict their own Type Metadata, which this library's earlier issuers never checked, so credentials they
  issued can be among them.
- **X.509 certificate chains: `x5c` on signing, and the end-entity key on verification** (issue
  [#46](https://github.com/moisesja/dataproofs-dotnet/issues/46); RFC 7515 §4.1.6; the Inline X.509 Certificates
  mechanism of draft-ietf-oauth-sd-jwt-vc-27 §2.5). Tracked downstream in moisesja/credentials-dotnet#33.
  - *Signing.* `JwsSigner.CertificateChain` (an `init` property) takes an `X509CertificateChain`, built with
    `X509CertificateChain.Create` from DER certificates, end-entity first. Every JWS that signer produces, compact
    or JSON, and so every JWT, VC-JOSE envelope, SD-JWT and SD-JWT VC, carries it as `x5c` in the **protected**
    header (standard padded base64, as §4.1.6 requires; -27 §2.5 reads it only there). Setting a chain whose
    end-entity key is not the signer's public key (`ISigner.PublicKey`), or whose end-entity Key Usage lacks
    `digitalSignature` (`X5C_KEY_USAGE`), throws `ArgumentException`, so the library never emits an `x5c` whose
    end-entity key is not the signer's or may not sign. A signer without a chain emits exactly the bytes it did
    before.
  - *Verification.* `JwsParser.ParseCompactWithCertificateChain`, `SdJwtVerifier.VerifyWithCertificateChain` and
    `SdJwtVcVerifier.VerifyWithCertificateChainAsync` (Type Metadata processing optional, through
    `TypeMetadataProcessingOptions`) take a **mandatory** hook, `Func<X509CertificateChain, bool>`, in place of the
    `kid` resolver. Calling one of them is what selects the X.509 mechanism: the token cannot (-27 §7.3). The key
    is always `x5c[0]`'s; the signature is checked with it; only then is the hook called, once, and the result is
    valid only when it returns `true`. The chain is on `JwsParseResult.CertificateChain`,
    `SdJwtVerificationResult.IssuerCertificateChain` and `SdJwtVcVerificationResult.IssuerCertificateChain`, and
    `X509CertificateChain.EndEntityPublicKey` gives the end-entity key as a `Jwk`. A `kid` beside `x5c` selects
    nothing and is not reported (`SignerKid` is empty, `SignerKidIsProtected` is `false`). Failures have stable
    codes at the start of the message: `X5C_MISSING`, `X5C_MALFORMED`, `X5C_UNSUPPORTED_KEY`, `X5C_KEY_USAGE` and
    `X5C_UNTRUSTED` (the hook said no); a signature that does not verify under the end-entity key is the existing
    `JoseCryptoException` / `ISSUER_SIGNATURE_INVALID`. `JwsParser` throws `MalformedJoseException` for
    `X5C_MALFORMED` and `JoseCryptoException` for the others; the SD-JWT verifiers return them in `Errors`. An
    exception from the hook propagates, as one from a `kid` resolver does.
  - *What a well-formed `x5c` is.* A JSON array of 1 to `X509CertificateChain.MaxCertificates` (10) strings, each
    canonical base64 (no base64url, no whitespace, padding required), each exactly one DER certificate whose
    `TBSCertificate` fields are in RFC 5280 order, no two identical. Where RFC 5280
    gives the schema, the certificate is read under DER rules field by field: each Name down to its attribute values
    (each RDN a non-empty SET OF in DER order), each AlgorithmIdentifier, and each extension, whose `extnValue` must
    hold exactly one DER TLV, no extension twice (RFC 5280 §4.2). Where the schema is open (attribute values, algorithm
    parameters, extension values), every nested TLV is read to a depth of 32, but only against the DER rules that hold
    whatever the schema: minimal lengths and tags; primitive encodings for the universal types DER always encodes
    primitively (BOOLEAN, INTEGER, the strings, OCTET STRING, NULL, OID, the time types and others), constructed ones
    for SEQUENCE, SET, EXTERNAL, EMBEDDED PDV and CHARACTER STRING; and DER's content rules for BOOLEAN, INTEGER,
    ENUMERATED, BIT STRING unused bits, NULL, OBJECT IDENTIFIER, UTCTime and GeneralizedTime. Without the schema, the
    order of a SET's elements (a SET is ordered by tag, a SET OF by octets), DEFAULT omission and a named bit list's
    trailing zeros cannot be judged, and are not. Not interpreted: the bytes of strings, OCTET STRINGs and REALs
    (character sets are type constraints, not encoding rules), and the contents of the signature and public-key BIT
    STRINGs, except the end-entity key. Tolerated where the schema is known: an explicit v1 version, an explicit
    critical `FALSE` and Key Usage trailing zero bits, which DER would omit, as certificate parsers generally do. No
    false rejects were found: the vendored RFC 7515 Appendix B chain parses, and so do certificates the platform
    validates carrying certificatePolicies (EV, ETSI qualified), eIDAS qcStatements, a Certificate Transparency SCT
    list, AIA, CRL distribution points, every subjectAltName form .NET builds, EKU, SKI and AKI, as does a schema-unknown
    SET in tag order; locally, 349 distinct real certificates (the macOS trust bundle and keychains, NuGet signing
    chains) parse, none `X5C_MALFORMED`. The end-entity key must be Ed25519, P-256, P-384 or secp256k1, with the
    `alg` that key's curve produces; RSA, Ed448, other algorithms and other named curves (P-521 among them) are
    `X5C_UNSUPPORTED_KEY`, and an EC key whose parameters are not a named curve is `X5C_MALFORMED`.
    `X509CertificateChain.Create` throws `MalformedJoseException` for `X5C_MALFORMED` and `NotSupportedException`
    for `X5C_UNSUPPORTED_KEY`. EC points are checked on their curve; Ed25519 keys are checked for length, and a key
    that is no curve point, or a small-order one, fails at the signature check, before the hook runs.
  - *Key Usage, checked by the library.* An end-entity certificate with a Key Usage extension that does not assert
    `digitalSignature` (RFC 5280 §4.2.1.3; critical or not; `contentCommitment` alone included) may not verify a JWS:
    the three verifiers refuse it with `X5C_KEY_USAGE` (`JoseCryptoException` from `JwsParser`) before using the key
    or calling the hook. This is a limit on the library's own use of the key, and the platform's `X509Chain` does not
    check it, so a hook built on it would otherwise accept a trusted key-agreement-only certificate as a signer. A
    certificate without the extension is unrestricted. `X509CertificateChain.Create` accepts such a chain: it is well
    formed. Extended Key Usage is not checked: its purposes are ecosystem-defined, so the hook checks the one its
    ecosystem requires. DER is read with the in-box
    `System.Formats.Asn1`, which performs no cryptography: no package was added.
  - **What the library does not check: the chain.** It performs no RFC 5280 path validation. It verifies no
    certificate signature and checks no validity period, basic constraints, Extended Key Usage, name chaining or
    order, revocation, policy, name constraint or critical extension, and it holds no trust anchor. RFC 7515 §4.1.6
    requires the recipient to validate the chain, and -27 §2.5 requires it to be validated "against a trust
    anchor permitted for the Issuer according to policy (a certificate in the x5c header parameter is not a trust
    anchor merely because it is included there)". That is the hook's job. NetCrypto, through which this library's
    cryptography must go (PRD §2.2), has no X.509 support and no RSA, and the platform's chain engine would
    bypass it. The new sample `Samples.X509CertificateChain` shows a hook built on `X509Chain` in
    `CustomRootTrust` mode, the verifier's anchors in `CustomTrustStore` and the `x5c` certificates only in
    `ExtraStore`. Under this mechanism the Issuer is the end-entity certificate's subject, and an `iss` claim is
    not authenticated by it (-27 §2.5): bind it yourself, for example through a Subject Alternative Name, or
    ignore it.

  The `x5c` support changes nothing for existing callers. `JwsParser.Parse`/`ParseCompact`,
  `SdJwtVerifier.Verify`, `SdJwtVcVerifier.VerifyAsync`/`VerifyWithTypeMetadataAsync` and
  `VcJose.VerifyCredential` never read `x5c`, so a token whose `x5c` is malformed still verifies through them
  as before, and `x5c` makes none of them refuse an input they accepted. (The SD-JWT verifiers refuse more in
  this release for other reasons: issues #45, #48 and #49.) No member was removed or changed. Not provided: `x5c` verification for detached-payload compact JWS
  and for the JWS JSON serializations (which never read `x5c`, protected or not), an asynchronous hook, and the
  COSE counterpart, `x5chain` (RFC 9360).
- **`bbs-2023` base proofs with a key that stays in a key store** (issue
  [#44](https://github.com/moisesja/dataproofs-dotnet/issues/44); PRD FR-12, AC-8). A new
  `Bbs2023Cryptosuite.CreateBaseProofAsync` overload takes a NetCrypto `ICapableKeyStore`, the key's alias and the
  `KeyInstanceId` the alias must hold, and no private-key bytes. Until now the overload that takes the BLS12-381 G2
  private key as bytes was the only way to issue `bbs-2023`, so an issuer that must not handle raw key material
  could not issue it at all.
  - **Before the store.** The new overload checks every input first, including the pointer and skolemization checks
    that need the document transformed.
  - **Calling the store.** It reads the public key with `GetInfoAsync(alias, instanceId)`, so an alias rebound to
    another key fails with `KeyNotFoundException` instead of signing. It then has the store sign with `SignBbsAsync`
    under `KeyStoreAlgorithms.BbsBls12381Sha256`.
  - **Checking the answer.** It verifies the signature it gets back before assembling the proof, so a store that
    answers with another key's signature, or a malformed one, issues no proof (`ProofGenerationException`). Store
    exceptions propagate unchanged.
  - **The HMAC key** stays the caller's to supply, 32 bytes as before. The holder receives it inside the base proof,
    so it is not signing-key material. Draw a fresh one per credential.
  - **The store sees the credential's selectively disclosable content.** A BBS signature covers the messages, not a
    hash of them, so `SignBbsAsync` receives the non-mandatory statements as N-Quads in the clear. The mandatory
    statements reach it only as a hash in the header, and the HMAC key not at all. Weigh this before signing with a
    remote key service.
  - **Same bytes.** BBS signing is deterministic, so for the same key and inputs the new overload's `proofValue` is
    byte-identical to the raw-key overload's. The raw-key overload emits the same bytes as before, and derivation
    and verification are unchanged.
  - **Copies at entry.** Both overloads now copy the proof options, the HMAC key and the pointers. The returned proof
    no longer shares the caller's `AdditionalProperties` dictionary, and its extension values and `@context` no
    longer live in the caller's `JsonDocument`s. `previousProof` can no longer be changed at all (issue #61, under
    *Fixed*). Changing or disposing the caller's options later therefore leaves the proof as issued.
  - **Reflection.** `CreateBaseProofAsync` is now overloaded, so a reflection lookup by name alone
    (`typeof(Bbs2023Cryptosuite).GetMethod("CreateBaseProofAsync")`) throws `AmbiguousMatchException`; pass the
    parameter types. No call in source binds to both overloads, whose required parameters differ in number and type.
    The analyzer rule RS0026, which flags two public overloads with optional parameters, is suppressed on the pair.
  - **Not provided:** a key store without `ICapableKeyStore`. A plain `IKeyStore` has no multi-message BBS
    operation.

  The sample `Samples.BbsSelectiveDisclosure` now issues through a key store.

### Fixed

- **Behaviour change: SD-JWT and SD-JWT VC verification refuses an expired or not-yet-valid credential** (issue
  [#45](https://github.com/moisesja/dataproofs-dotnet/issues/45)). RFC 9901 §7.1 step 6, part of the verification the
  Holder or Verifier "MUST perform": "Check that the SD-JWT is valid using claims such as nbf, exp, and aud in the
  processed payload, if present". draft-ietf-oauth-sd-jwt-vc-27 §2.2.2.3: `nbf` is "The time before which the
  Verifiable Digital Credential MUST NOT be accepted", `exp` the time "after which the Verifiable Digital Credential is
  no longer valid". Neither `SdJwtVerifier` nor `SdJwtVcVerifier` read them: an SD-JWT VC with `exp: 1000000000`
  (2001), or with `nbf: 4102444800` (2100), verified with `IsValid = true`. **Credentials that verified before now
  fail when they have expired or are not yet valid, including credentials this library issued.**
  - *What is checked.* The top-level `nbf` and `exp`, both optional, at `SdJwtVerificationOptions.CurrentTime`
    (default: now) with `SdJwtVerificationOptions.ClockSkew` (default: 2 minutes), which until now applied only to the
    Key Binding JWT. A presentation fails with `SD_JWT_NOT_YET_VALID` before `nbf` − skew, and with `SD_JWT_EXPIRED` at
    or after `exp` + skew: RFC 7519 §4.1.4 says the time "MUST be before" `exp`, so with no skew the instant `exp` itself
    is refused, while `nbf` itself is accepted (§4.1.5, "after or equal"). A present value must be an RFC 7519
    NumericDate, a JSON number of seconds from -62135596800 to 253402300799 (0001-01-01 to 9999-12-31; exponent
    notation and fractions allowed, fractions kept to the 100 ns tick); anything else is `SD_JWT_NBF_INVALID` or
    `SD_JWT_EXP_INVALID`, at any time. Both claims are judged, so a presentation can carry two codes. Each code starts
    the error message, as every SD-JWT code does.
  - *Where.* `SdJwtVerifier.Verify` and `VerifyWithCertificateChain`, and `SdJwtVcVerifier.VerifyAsync`,
    `VerifyWithTypeMetadataAsync` and `VerifyWithCertificateChainAsync`: the check is in the verification all five
    share, after the Disclosures are processed and before the Key Binding JWT, the SD-JWT VC claim rules (`vct`,
    `aka_vcts`, the must-not-disclose rule) and any Type Metadata retrieval, so an expired credential never makes a
    resolver fetch. The SD-JWT VC media-type check (`VC_MEDIA_TYPE_INVALID`) still comes first. The generic verifier enforces it too,
    because RFC 9901 §7.1 does: it reads the processed payload, so an `exp` an Issuer made selectively disclosable is
    checked when disclosed (RFC 9901 §9.7 says Issuers must not do this). An SD-JWT VC that verifies has had the value
    the Issuer signed in the clear at the top level judged, and no other. A Disclosure cannot add an `nbf` or `exp`
    beside it (the name clash is `DISCLOSURE_INVALID`), and one that adds it where there is none is always refused: with
    the window's code (`SD_JWT_EXPIRED`, `SD_JWT_NOT_YET_VALID`, `SD_JWT_EXP_INVALID`, `SD_JWT_NBF_INVALID`) when its
    value fails the window, and with `VC_DISALLOWED_DISCLOSURE` otherwise. A nested claim such as
    `credentialSubject.exp` is an ordinary claim and is not judged.
  - *The Key Binding JWT's own `nbf` and `exp`*, when present, are judged the same way (RFC 9901 §7.3 step 5.h: "a valid
    JWT in all other respects, per [RFC7519]"), with the new codes `KB_JWT_NOT_YET_VALID`, `KB_JWT_EXP_PASSED`,
    `KB_JWT_NBF_INVALID` and `KB_JWT_EXP_INVALID`. `KB_JWT_EXPIRED` keeps its one meaning, the `iat` age bound
    (`MaxKeyBindingAge`), and one result can carry it beside `KB_JWT_EXP_PASSED`. The KB-JWT's claims never stand in
    for the Issuer's. This library's Key Binding JWTs carry neither claim, so none it made is affected.
  - *This narrows what the verifiers accept.* An expired or not-yet-valid credential, and a non-number `nbf`/`exp`, are
    invalid under RFC 9901 and RFC 7519. A NumericDate before year 1 or after year 9999 (such as `1e20`) is valid under
    RFC 7519 and is now refused as `*_INVALID`, by the verifiers and by both issuers: no conformant Issuer has a use for
    it, and refusing is the fail-closed reading in every direction. That part narrows the accept-set for spec-valid
    input. `nbf` later than `exp` is not refused as such: with no skew it fails at every instant.
  - *This library's own output.* `SdJwtIssuer` and `SdJwtVcIssuer` have never added `nbf` or `exp`, and have signed the
    caller's values as given in every release from 0.1.0-preview.1 to 2.0.0. A credential they issued with an `exp` that
    has now passed, or an `nbf` still ahead, verified until this release and now fails. One they issued with a
    non-number `nbf` or `exp` (a string, or a .NET `DateTimeOffset` placed in the claims set, which serializes as one),
    or with a NumericDate outside -62135596800 to 253402300799 (such as `1e20`, which 2.0.0 signed and verified), now fails at
    every instant, and both issuers now refuse to sign it, throwing `MalformedJoseException` with the verifier's code. The issuers do not judge the time: a credential valid from tomorrow is still issued.
  - *What to do.* Issuers write `nbf` and `exp` as seconds (`DateTimeOffset.ToUnixTimeSeconds()`) and reissue
    credentials whose holders still need them after `exp`. Verifiers that must judge a credential at another instant,
    such as an audit of past presentations, set `CurrentTime`; one that tolerates more clock drift raises `ClockSkew`.
    Tests that verify fixed credentials should set `CurrentTime` too, or they will start failing at the credential's
    `exp`. No member was added, removed or changed.

- **SD-JWT: the Key Binding JWT age bound no longer throws `OverflowException`.** With `MaxKeyBindingAge` set,
  `maxAge + ClockSkew` overflowed `TimeSpan` when both were large (for example `ClockSkew = TimeSpan.MaxValue`), and the
  exception escaped `SdJwtVerifier.Verify` and `SdJwtVcVerifier.VerifyAsync`. It is now compared without overflow.
  Found by the issue #45 work.

- **SD-JWT VC: the must-not-disclose rule follows a claim's position, not its name** (issue
  [#48](https://github.com/moisesja/dataproofs-dotnet/issues/48)). -27 §2.2.2.3: "The following
  registered JWT claims, including any of their subclaims, when used in the SD-JWT component of an
  SD-JWT VC, MUST NOT be included in Disclosures". The listed names are JWT claims, members of the
  top-level claims set. `SdJwtVcVerifier` compared each presented Disclosure's claim name with the list
  wherever the Disclosure sat. It now applies to every reserved name the positional rule #49 introduced for
  `aka_vcts`, which reads what the issuer signed: it refuses a reserved top-level claim that is absent from
  the issuer-signed payload but present in the processed one (a presented Disclosure supplied it), and a
  reserved claim whose signed value holds a disclosure site anywhere inside it, an `_sd` array with at
  least one digest or a `{"...": digest}` element placeholder, whether the Disclosure is attached, withheld
  or a decoy. Judging only the presented Disclosures would not do: withholding one changes a registered
  claim under the same signature, for example `status.status_list` dropped from `status`. The behaviour
  changes follow, one each way:
  - *Now accepted:* a Disclosure of a nested claim that only shares a reserved name, such as
    `credentialSubject.status`, `credentialSubject.exp` or `credentialSubject.iss` made disclosable with
    `DisclosureFrame.DiscloseObjectProperties("credentialSubject", "status")`. `SdJwtVcIssuer` issued
    these in every release, and `SdJwtVcVerifier` refused its own output with `VC_DISALLOWED_DISCLOSURE`.
    They now verify. Nothing to do.
  - *Now refused, which narrows what the verifier accepts:* a credential with selectively disclosable
    content inside a reserved claim, such as a member of `status` or `cnf` at any depth, or an element of
    `aka_vcts` or of an array inside `status`, whether its Disclosure is attached or withheld, and whether
    the reserved claim around it is in the clear or is itself a Disclosure. 2.0.0 verified these. -16 did
    not say whether a reserved claim's subclaims could be disclosed; -19 added "including any of their
    subclaims", so under the pinned -27 such a credential is invalid. The failure is
    `VC_DISALLOWED_DISCLOSURE: SD-JWT VC claim 'status' MUST NOT have selectively disclosable sub-claims or
    elements (...)`. The message for a reserved claim disclosed at the top level is unchanged. An empty
    `_sd` array inside a reserved claim carries no digest and is accepted (RFC 9901 §4.2.4.1).
  - *Also refused, and valid: decoy digests inside a reserved claim. This narrows the accept-set for
    spec-valid input.* RFC 9901 §4.2.5: "Decoy digests MAY be added both to the _sd array for objects as
    well as in arrays", and -27 §2.2.2.3 forbids Disclosures, not digests, so a credential with only decoys
    there is conformant. A verifier cannot tell a decoy from a withheld Disclosure, and the withheld case is
    the one -27 forbids, so the check fails closed. This library's 2.0.0 output is among it: the generic
    `SdJwtIssuer` with `typ: dc+sd-jwt`, a `DecoyDigestCount` above zero and a frame entry such as
    `DiscloseObject("status", new DisclosureFrame())` put decoys inside `status`, and that credential
    verified until this release.
  - *This library's own output:* `SdJwtVcIssuer` has refused a `DisclosureFrame` entry of any kind on
    `iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity` or `status` in every release from 0.1.0-preview.1
    to 2.0.0, every Disclosure such an entry makes sits at or under that claim, and it adds decoys only to
    objects a frame entry processes, so none of its output is newly refused, apart from the `aka_vcts`
    element Disclosures under *Changed* and a claims set in which the caller itself built a disclosure
    site inside a reserved claim. A credential built with the generic `SdJwtIssuer`,
    `typ: dc+sd-jwt` and a frame entry on a reserved claim is newly refused.
  - *What to do:* issuers keep `iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts` and
    `status` wholly in the clear. A verifier that receives credentials with Disclosures inside them needs
    the issuer to reissue them.

  `SdJwtVcIssuer` refuses the same frames as before, and its message now adds "and neither may any of its
  subclaims". It now also throws `MalformedJoseException` for a claims set whose reserved claim holds a
  disclosure site the caller built, which it used to sign as given. It serializes the claims once, checks
  that JSON and signs it, so a `JsonValue` wrapping a .NET object that serializes with an `_sd` member is
  caught too, and a claims set that serializes with a duplicate member name (RFC 7519 §4: claim names
  "MUST be unique") now throws `MalformedJoseException` instead of being signed and refused at
  verification. A claims set the serializer cannot write still fails through the returned task. A Disclosure
  referenced from the top-level `_sd` hides its name behind its digest, so when it is withheld no verifier
  can tell that it was a reserved claim: keeping those claims in the clear is the issuer's duty. The
  generic `SdJwtVerifier` does not apply the rule, which belongs to the SD-JWT VC profile.

- **SD-JWT: a digest that appears twice anywhere in the payload is refused** (RFC 9901 §7.1 step 4: "If
  any digest value is encountered more than once in the Issuer-signed JWT payload (directly or recursively
  via other Disclosures), the SD-JWT MUST be rejected"). `SdJwtVerifier` and `SdJwtVcVerifier` refused a
  repeat only within one `_sd` array, or when a presented Disclosure was referenced twice; a decoy or
  withheld digest that repeated across `_sd` arrays and `...` placeholders was accepted. Such an SD-JWT now
  fails with `DISCLOSURE_INVALID`, and the message for every repeat is now `An SD-JWT digest appears more
  than once in the payload, ...`. Every newly refused input is invalid under RFC 9901. *This library's own
  output* is affected only where the caller built the repeat: `SdJwtIssuer` salts every Disclosure and draws
  every decoy at random, but in every release from 0.1.0-preview.1 to 2.0.0 it, and `SdJwtVcIssuer` through
  it, copied a caller's claims as given, so a claims set that already held a digest twice, in its own `_sd`
  arrays or `...` placeholders, was signed and verified. It is now refused at verification, and both issuers
  refuse to sign it (see "`SdJwtIssuer` does not sign what its own verifier refuses", below). Found by the issue #48 adversarial pass; it is a separate
  commit in that PR.

- **SD-JWT: an `_sd_alg` below the top level is refused, verifying and issuing.** RFC 9901 §4.1.1:
  `_sd_alg` "MUST appear at the top level of the SD-JWT payload. It MUST NOT be used in any object nested
  within the payload." The reconstructor skipped an `_sd_alg` member at every depth, so a nested one
  vanished from the processed payload unread, with any digests under it out of reach of the step 4 check,
  and the SD-JWT verified. `SdJwtVerifier` and `SdJwtVcVerifier` now fail with `DISCLOSURE_INVALID` when
  a nested object carries `_sd_alg` in the clear, inside a disclosed value, or through a Disclosure named
  `_sd_alg`; and a Disclosure named `_sd_alg` beside the top-level one is a name clash (§7.1 step
  3.c.ii.3: "If the claim name already exists at the level of the _sd key, the SD-JWT MUST be rejected"),
  where it used to replace `_sd_alg` in the processed payload. Every newly refused input is invalid under
  RFC 9901.
  - *This library's own output, which this narrows:* in every release from 0.1.0-preview.1 to 2.0.0
    `SdJwtIssuer` (and `SdJwtVcIssuer` through it) wrote `_sd_alg` at the top level only, and copied a
    caller's claims as given. So its output carries a nested `_sd_alg` only when the caller's claims set
    held a member named `_sd_alg` below the top level, in the clear, inside a value that a `DisclosureFrame`
    entry discloses, or as the target of a nested frame entry; or a top-level `_sd_alg` that the frame
    discloses. Every release verified those, dropping the member. They are now refused. Default issuance,
    and every frame over claims without such a member, never produced the shape and is unaffected.
  - *What to do:* rename the claim. A verifier that holds such credentials needs them reissued.

- **SD-JWT: `SdJwtIssuer` does not sign what its own verifier refuses.** Before signing, it parses back the
  payload bytes and the encoded Disclosures and reconstructs them as `SdJwtVerifier` does with every
  Disclosure presented, and throws `MalformedJoseException` if that fails. Besides the nested `_sd_alg`
  above, it now refuses, where it used to sign an SD-JWT its verifier then refused: a claims set that
  serializes with a duplicate member name (RFC 7519 §4), a frame entry on a claim named `_sd` or `...`
  (RFC 9901 §4.2.5.1), a caller-built `_sd` that does not reconstruct, and a claims set nested deeper
  than the reconstruction bound of 64 (depth 63 and beyond). The check reads the serialized form, so a
  .NET object inside a `JsonValue` is covered. It adds one parse and one reconstruction per issuance.
  Found by the PR #54 review and the issue #48 adversarial passes; a separate commit in that PR.
- **Data Integrity: a proof no longer shares the caller's proof options** (issue
  [#61](https://github.com/moisesja/dataproofs-dotnet/issues/61)). Affected: the JCS suites (`eddsa-jcs-2022`,
  `ecdsa-jcs-2019`), the RDFC suites (`eddsa-rdfc-2022`, `ecdsa-rdfc-2019`) and both legacy suites in both variants.
  Each built the proof from a shallow copy of the options, checked it, then awaited the signer. The returned proof
  kept the caller's `AdditionalProperties` dictionary, and the `JsonElement`s behind the extension values and the
  options' `@context`. The window matters for any signer that awaits, such as a NetCrypto `KeyStoreSigner`, a remote
  KMS or an HSM:
  - an extension member changed while the signer ran was signed with its old value and returned with its new one, so
    the proof did not verify;
  - a reserved name added then, such as `proofValue`, got past the FR-2 check, which had already run;
  - a change made after the call changed the issued proof;
  - once the caller disposed its `JsonDocument`, serializing the proof threw `ObjectDisposedException`.

  Each suite's `CreateProofAsync` and `DataIntegrityProofPipeline.AddProofAsync` now copy the options before reading
  them. The copy rebuilds the extension dictionary and clones `@context` and every extension value. `bbs-2023`
  already copied its options (issue #44) and now runs the same code. The pipeline's copy also covers a suite this
  library does not ship. Emitted bytes do not change. The returned proof's `AdditionalProperties` is now a new
  `Dictionary<string, JsonElement>`, not the caller's object.
  - **Faults the copy reports.** The copy is the first step to read the options, so it reports what they hold with
    `ProofGenerationException`, and the message never quotes a member name (FR-23). Three faults:
    - a JSON value whose `JsonDocument` has been disposed, which used to escape as a raw `ObjectDisposedException`;
    - an extension member with a null name;
    - a name that a dictionary with its own comparer lists twice.

    **One input that worked is refused.** The JCS and RDFC suites used to replace the options' `@context` with the
    document's without reading it, so a disposed one went unnoticed. It is now refused like any other disposed
    value. Because the copy runs first, these faults are also reported before the document's.
  - **Legacy RDFC no longer reads the document after signing.** Both legacy suites' RDFC variant took the proof's
    `@context` from the caller's document a second time once the signer returned. A document disposed while the
    signer ran then threw `ObjectDisposedException` after the signature was made. A document whose buffer changed in
    that time gave a proof whose `@context` differed from the one signed. The proof is now fixed before signing.
  - **`PreviousProofReference` is immutable.** `Values`, typed `IReadOnlyList<string>`, returned the backing
    `string[]`, so `((string[])reference.Values)[0] = "…"` changed every proof and options object that shared the
    reference. It now returns a list that implements `IReadOnlyList<string>` and nothing else, so no public interface
    reaches the ids. A cast to `string[]`, to a writable interface such as `IList<string>`, or to the non-generic
    `ICollection` (whose `SyncRoot` is how `ReadOnlyCollection<T>` hands out the array it wraps) throws
    `InvalidCastException`. The declared type is unchanged.

### Why this is a minor and not a major

The owner fixed this release at 2.1.0 on 2026-11-19, before the six issues were worked, and every change in it
was held to that. The owner added issue #44 to it on 2026-11-20, under the same rule. Under the versioning policy in [`RELEASING.md`](RELEASING.md):

- *The public API only adds, which by itself makes this a minor* (SemVer §7, "MINOR version ... MUST be
  incremented if new, backward compatible functionality is introduced to the public API").
  `DataProofsDotnet.Jose`'s `PublicAPI.Unshipped.txt` gains 90 entries and `DataProofsDotnet.Rdfc`'s gains 1
  (issue #44). Neither loses any, and no other package's API changed. No existing member changed or gained a
  parameter, so nothing breaks at binary level either. Rdfc's entry is a second `CreateBaseProofAsync` overload, so
  only a reflection lookup by that name alone, without parameter types, becomes ambiguous. No new property has a
  `set` accessor; four have `init`.
- *`[Obsolete]` on `SdJwtVcConstants.TransitionalMediaType` comes closest to a major.* The constant, its value and
  its `PublicAPI` entry stay, and SemVer §7 makes a deprecation a minor ("It MUST be incremented if any public API
  functionality is marked as deprecated"). But the policy calls a change non-breaking when "no source has to
  change", and a consumer that uses the constant and treats warnings as errors does have to change its source: it
  writes the literal or suppresses CS0618. Every other consumer compiles unchanged, and compiled code is unaffected,
  since the constant's value is copied into it. This release counts that as a deprecation, not as the source break
  the 2.0.0 rule makes a major.
- *Emitted output does not change.* For input that 2.0.0 issued, the issuers emit the same bytes, and `x5c`
  appears only when the caller sets `JwsSigner.CertificateChain`.
- *`PreviousProofReference.Values` no longer hands out its backing array (issue #61).* Its declared type,
  `IReadOnlyList<string>`, is unchanged and never promised an array. Code that cast it to `string[]` or to another
  collection interface the array implements, such as `IList<string>`, still compiles but now throws
  `InvalidCastException`. This release counts that as a fix, not a break.
- *The accept-set narrows, partly for spec-valid input, which is minor or major material and never a patch.* Most of
  what is newly refused was invalid under the governing RFC: expired and not-yet-valid credentials and non-number
  times (RFC 9901 §7.1 step 6, §7.3 step 5.h; RFC 7519 §4.1.4, §4.1.5), a repeated digest (RFC 9901 §7.1 step 4), a
  nested `_sd_alg` (§4.1.1) and a Disclosure named `_sd_alg` beside the top-level one (§7.1 step 3.c.ii.3). Five
  narrowings refuse input that was spec-valid, or that the draft 2.0.0 pinned, -16, asked Verifiers to accept:
  - a NumericDate outside -62135596800 to 253402300799 seconds (the years 0001 to 9999), which RFC 7519 allows;
  - decoy digests inside a reserved claim, which RFC 9901 §4.2.5 and -27 allow;
  - `typ: vc+sd-jwt`, which -16 asked Verifiers to accept "for a reasonable transitional period", although its
    Issuers "MUST use dc+sd-jwt";
  - a selectively disclosable or free-form `aka_vcts`, a claim -16 did not register;
  - Disclosures inside a reserved claim's subclaims, which -16 left open.
- *None of them makes it a major, by this release's judgment.* `RELEASING.md` asks whether a conformant peer could
  plausibly be depending on the old behaviour today. For the three draft shapes it could not: a peer conforming to
  -19 or later, and so to the -27 this release pins, sends none of them. The two RFC shapes are less clean. A
  conformant peer could send them, and this library's 2.0.0 issuers could produce both: both issuers signed
  `exp: 1e20`, and the generic `SdJwtIssuer` could put decoys inside `status` (the `SdJwtVcIssuer` never did from
  a `DisclosureFrame`). They are refused anyway, because neither has a known use and refusing fails closed: an
  `exp` past 9999 means nothing for a credential, and a verifier cannot tell decoys inside a reserved claim from the
  withheld Disclosures -27 forbids.

## [2.0.0] - 2026-11-02

**This is a major release.** The four RDFC constructor changes under Changed remove actual
parameterless constructors: ordinary `new X()` calls remain valid, but `where T : new()` consumers must
change source, and recompiling alone is not the complete migration. It also changes the bytes RDFC and
bbs-2023 sign, so inventory stored proofs as described under Fixed, and it refuses some proofs that
used to verify, listed under Security.

### Security

- **The proof options a verifier acts on are now bound to the signature**
  ([GHSA-6fxh-mc39-94vc](https://github.com/moisesja/dataproofs-dotnet/security/advisories/GHSA-6fxh-mc39-94vc)).
  Verification decides on a proof's JSON members, an RDFC or bbs-2023 signature covers the RDF those
  members expand to, and `@context` is not signed. So anyone holding a proof, with no key and default
  verification options, could spell the same RDF with other JSON, by adding a term to the proof's
  `@context` or to the document's. Each of these verified on 1.5.0:
  - an expired proof, with `expires` renamed under a term for the same predicate, so that the verifier
    saw no expiry;
  - a `challenge` the issuer never signed, in a member that spelled something already signed, so that a
    proof passed for a verifier's fresh challenge;
  - a `domain` swapped for another the same way;
  - a `proofPurpose` name mapped to the IRI that was signed, so that a proof made for `assertionMethod`
    passed as `authentication`;
  - a custom `proofPurpose` respelled from its term to its IRI, so that a proof passed a policy written
    for a spelling the issuer never used;
  - a signed node nested in the proof moved to the outer proof with `@reverse`, which leaves the dataset
    unchanged, so that its purpose answered for the proof's. The node could be of another proof type:
    `eddsa-rdfc-2022` and the legacy RDFC `Ed25519Signature2020` build the same signing input.
  - a proof signed with two types and statements under each type's vocabulary, presented as the other
    type, so that the purpose signed there answered for the proof's. This takes an issuer whose context
    defines a second term for `@type`, and no published context does.

  A proof now verifies only if the members the library reads are what was signed. The suites read the
  canonical N-Quads they hash and compare them with `id`, `type`, `cryptosuite`, `created`, `expires`,
  `verificationMethod`, `proofPurpose`, `challenge`, `domain`, `nonce` and `previousProof` in both
  directions, so a member renamed away and a member the issuer never signed both fail with
  `PROOF_VERIFICATION_ERROR`. The proof node they compare is the one default-graph node nothing points
  at, and it must have exactly one type, so the signed data decides both, not the presented JSON. A
  signed purpose IRI has one accepted spelling: its registered name, else the name the IRI ends in, else
  the whole IRI. The same check runs at creation, which throws `ProofGenerationException` rather than
  issue a proof that could not verify. This affects `eddsa-rdfc-2022`, `ecdsa-rdfc-2019`,
  `bbs-2023` and the RDFC variant of `Ed25519Signature2020` and `EcdsaSecp256r1Signature2019`. The JCS
  suites sign the JSON itself and were not affected. No public API changes, and no signed bytes change.
  Versions up to 1.5.0 have no mitigation in the library: upgrade.

  **Newly refused.** A member is read from the predicate the published contexts give it, or from its
  name in the vocabulary of the proof's own type, which is how a proof reads under
  `credentials/undefined-terms/v2`. These shapes are allowed by the specifications and verified before,
  but the library cannot confirm what they say, so they are refused:
  - a context mapping a modeled member to any other predicate;
  - a proof with no `rdf:type` statement, as under a bare `@vocab` that leaves `type` unaliased;
  - a proof with more than one, as under a second term for `@type`;
  - a compact IRI under a custom prefix in `id`, `verificationMethod` or `previousProof`, whose JSON
    spelling is not the signed IRI;
  - a `proofPurpose` in any spelling but that one, so `approve` is accepted for
    `https://example.org/approve` and the IRI itself is not;
  - a proof configuration without exactly one node nothing points at, such as one using `@included` or
    a `@reverse` member, or a nested member pointing back at the proof's own `id`.

  **Not covered.** The library does not know what an unmodeled member
  (`DataIntegrityProof.AdditionalProperties`, such as a ZCAP `capabilityChain`) or a document claim
  means, so neither is compared. An application that acts on one must pin its contexts, with
  `ProofVerificationOptions.KnownContexts` and approved context content or with contexts it supplies
  itself. Two issuer choices still fall outside the guarantee, and no published context makes either: a
  context mapping a modeled member to a predicate of another name can lose that member to a rename, and
  another stack's proof whose outer node is pointed at by a proof-shaped node it signed reads as that
  node. This library refuses to issue the second. A custom purpose's short name also does not say which
  namespace it came from: `https://a.example/approve` and `https://b.example/approve` both read as
  `approve`, so a verifier relying on an issuer's custom purposes should expect that of its issuers.

### Added

- **Legacy suites can verify the constructed variant only.** A legacy proof does not say whether
  it was signed over JCS or RDFC, so `Ed25519Signature2020Cryptosuite` and
  `EcdsaSecp256r1Signature2019Cryptosuite` verify under the variant they were constructed with and
  then fall back to the other. A verifier whose profile allows one variant also accepted proofs
  made with the other: zcap-dotnet, which signs only over RDFC, accepted JCS-variant proofs. That
  is not a forgery, because JCS signs the bytes verbatim, but it accepts input outside the profile.

  The new enum `LegacyVariantVerification` and a third optional constructor parameter on both suites,
  `verification = LegacyVariantVerification.Both`, let a verifier pass `ConstructedVariantOnly` to
  turn the fallback off. In that mode, an RDFC data-loss failure is reported as
  `DATA_LOSS_DETECTION_ERROR`, as in the RDFC Data Integrity suites. This lifts the dual-variant
  limitation listed under 1.5.0 for verifiers that opt in.

- **`ProofVerificationOptions.KnownContexts`: context URI allowlisting.**
  A proof over RDF binds the statements, not the JSON that compacted them, so a holder can present
  a verified document under a `@context` that reads its terms differently (`boards` as `sails`); it
  verified here and on the reference implementation alike. The specification's answer is that
  applications MUST accept only known contexts, after the proofs are verified, and the pipeline had
  no option for it. With `KnownContexts` set, every `@context` in the secured document, at any depth,
  must hold only listed IRIs; an unlisted value, an inline context object or a `null` fails the
  document with a document-level `PROOF_VERIFICATION_ERROR`. Unset, nothing is checked, as before.
  The check runs before the proofs, because the suites load contexts while they verify: a context a
  document names loads only if listed. This does not authenticate its contents. Listing a
  context also trusts what it references, whose imports, scoped contexts and redirects load with it. A
  refused document has no per-proof results, so read `Verified`, not `ProofResults`. §2.4.1 orders the
  check after the proofs but allows a different ordering that gives the same protections. A nested `@context` follows the root's rule rather than failing
  outright as §4.6 step 3 reads, because the JCS suites copy `@context` into each proof and a
  presentation embeds credentials with their own. The option alone does not provide all §4.6
  protections: use approved immutable contexts or approved hashes (including dependencies), and
  separately enforce any exact-context sequence/nesting policy. A first-fetch network cache does
  not establish approved semantics. The list is a set, so
  order is not compared. Every key named `@context` counts, including one inside a JSON literal,
  because telling a literal apart takes processing the contexts: a term's type can make one, and
  `@value` is a keyword only outside a container map. So a literal holding that key, as a JSON Schema
  under `credentials/v2`'s `jsonSchema` can, fails the document unless the key's value is a listed
  IRI. Found by the adversarial review of the bbs-2023 rework (PR #42).

### Changed

- **RDFC canonicalization carries a string's base direction instead of refusing it** (issue
  [#40](https://github.com/moisesja/dataproofs-dotnet/issues/40)). 1.5.0 refused any document that
  uses `@direction`, because dotNetRDF's default JSON-LD→RDF conversion drops it, so earlier versions
  signed `ltr` and `rtl` as the same bytes. The processor now runs with JSON-LD 1.1
  `rdfDirection: i18n-datatype`: `{"@value":"x","@language":"ar","@direction":"rtl"}` is signed as
  `"x"^^<https://www.w3.org/ns/i18n#ar_rtl>` (the language lowercased, as that algorithm requires;
  `#_rtl` without a language), and flipping the direction breaks the proof. Affects `eddsa-rdfc-2022`,
  `ecdsa-rdfc-2019`, `bbs-2023` and the Legacy RDFC variant. The VCDM 2.0 test suite's
  "name/description with language and direction" credentials now issue and verify.

  This is the representation the reference Data Integrity implementations sign with: jsonld-signatures
  and the `eddsa-rdfc-2022`, `ecdsa-rdfc-2019` and selective-disclosure (`di-sd-primitives`)
  cryptosuites built on it all canonize with `rdfDirection: 'i18n-datatype'`. The Data Integrity
  specifications name no representation, so it is an unstated profile parameter. The issue proposed an
  opt-in with the refusal kept as the default, on the premise that a lossless implementation goes beyond
  what others verify; the premise was inverted, since a refusing verifier could not process what those
  issuers sign. A verifier whose JSON-LD processor drops direction, the JSON-LD default, does not
  verify these proofs, as it does not verify theirs. Checked against jsonld.js 9.0.0 with
  `rdfDirection: 'i18n-datatype'`: the canonical N-Quads are byte-identical for directional value
  objects, the VCDM 2.0 §11.1 shapes. Three differences are on its side, and a proof over such a
  document does not verify across the two. It drops a context-level default `@direction` whenever a
  scoped context applies, because its active-context clone keeps `@language` and `@vocab` but not
  `@direction` (dotNetRDF follows JSON-LD 1.1 API §5.3.2 and signs it). That reaches every
  `credentials/v2` credential that sets one, since `VerifiableCredential` is a type-scoped term, so
  issuers should write the direction on the value object instead. It emits an identical quad twice for
  a literal spelled both as a directional string and with its explicit `i18n#` datatype, where a
  dataset holds it once. And it signs a number's direction away silently, where this library refuses.

  This change alters no accepted input: direction-free documents are unaffected by it,
  direction-bearing ones were all refused, and proofs made before 1.5.0 over such documents verify in
  neither version. (The RDFC-1.0 fix under Fixed does change bytes for some documents.) Still refused, with `JsonLdDataLossException` (`DATA_LOSS_DETECTION_ERROR` on
  verify): a boolean or a number with a `@direction`, whose direction dotNetRDF (like jsonld.js) drops
  when it types the value as an XSD literal; JSON-LD 1.1 API §8.2.2 would apply the i18n datatype to
  the lexical form instead, so the refusal follows the processor, not the text.
  An explicit `https://www.w3.org/ns/i18n#…` datatype and the directional string it spells out are one
  RDF literal, as `1` and `1.0` are. No public API changes.
- **One public constructor each for `RdfcDocumentCanonicalizer`, `EddsaRdfc2022Cryptosuite`,
  `EcdsaRdfc2019Cryptosuite` and `Bbs2023Cryptosuite`:** `(IDocumentLoader? documentLoader = null)`
  and `(IRdfCanonicalizer? canonicalizer = null)`, `null` meaning the offline default. Each had `()`
  beside `(X)`, which made `ActivatorUtilities.CreateFactory(type, Type.EmptyTypes)` and
  `ActivatorUtilities.CreateInstance` with a provider that is not `IServiceProviderIsService` throw
  "Multiple constructors accepting all given argument types": the defect PR #39 fixed for the Legacy
  suites, found on these four by the same activation probe. `RdfcActivationCompatibilityTests` runs
  `CreateFactory`, `CreateInstance` with and without `IServiceProviderIsService`, `AddSingleton(type)`
  and `Activator` on all four. Every 1.5.0 call shape (`new X()`, `new X(dependency)`) compiles and
  binds. Migration: an assembly compiled against 1.5.0 must be rebuilt (`MissingMethodException` on
  `new` until then, as for the Legacy suites); `new X(null)` now means the default instead of throwing
  `ArgumentNullException`; `Activator.CreateInstance(typeof(X))` and a `where T : new()` constraint
  no longer apply, since there is no parameterless constructor (no occurrence in this repository,
  zcap-dotnet or credentials-dotnet).
- The default, `LegacyVariantVerification.Both`, keeps the fallback and its result codes, and
  emitted bytes are unchanged. An undefined `LegacyVariantVerification` value throws
  `ArgumentOutOfRangeException` rather than acting as `Both`, and so does an undefined
  `LegacyCanonicalization` value, which 1.5.0 silently treated as `Jcs`. Both come out of
  configuration binding or `Enum.TryParse` of a stray number, and a verifier built that way would
  accept exactly the variant it was configured to refuse. `Both` is the enum's zero value and the
  constructor default, so a verifier that requires `ConstructedVariantOnly` sets it in code or
  validates its bound options; a missing configuration key yields `Both`.
- Each suite still has exactly one public constructor, and every parameter has a default, so
  `ActivatorUtilities.CreateFactory`, `ActivatorUtilities.CreateInstance` (with or without an
  `IServiceProviderIsService` provider) and Microsoft DI registration by type activate the suites as
  they did in 1.5.0: they fill the parameters a caller omits from the defaults.
  `ActivationCompatibilityTests` runs each of those paths on both suites. With two public
  constructors, `CreateFactory` (with any provider) and `CreateInstance` without
  `IServiceProviderIsService` throw "Multiple constructors accepting all given argument types".

### Migration note — recompilation required for the legacy suite constructors

Source-compatible, **not binary-compatible**, as with `JwsSigner` in 1.3.0.
`Ed25519Signature2020Cryptosuite..ctor(LegacyCanonicalization, IRdfCanonicalizer)` and
`EcdsaSecp256r1Signature2019Cryptosuite..ctor(LegacyCanonicalization, IRdfCanonicalizer)` are replaced
by `..ctor(LegacyCanonicalization, IRdfCanonicalizer, LegacyVariantVerification)`. An optional parameter
does not preserve the old CLR method token, so an assembly compiled against 1.5.0 or earlier throws
`MissingMethodException` at its first `new` of a legacy suite if this assembly is dropped in without a
rebuild. No source change is needed: recompile, and every existing call shape (`new Suite()`,
`new Suite(LegacyCanonicalization.Rdfc)`, `new Suite(variant, canonicalizer)`) binds to the new
default. Reflection that names the 1.5.0 signature exactly has the same step:
`Activator.CreateInstance(type, canonicalization, canonicalizer)` and `GetConstructor` with those two
parameter types find no constructor until the third parameter is named; callers that pass
`BindingFlags.OptionalParamBinding` are unaffected, as are `ActivatorUtilities` and Microsoft DI, which
fill defaults (see Changed). This is accepted under this
repository's policy (`RELEASING.md`: binary compatibility is not a release constraint; downstream is
rebuilt) and recorded here because it is a real migration step. The public .NET API change is
source-additive for these legacy constructors alone; the separate RDFC constructor changes above
require the combined release classification stated at the top of this entry.

### Fixed

- **RDFC canonicalization corrects tied-node labels and follows Unicode code-point ordering.** This changes
  the signed bytes of some documents; see below. dotNetRDF 3.5.1's `RdfCanonicalizer` labels tied blank
  nodes in the wrong order ([dotnetrdf/dotnetrdf#917](https://github.com/dotnetrdf/dotnetrdf/issues/917)).
  It never removes uniquely-hashed nodes from its work list, and its check for nodes that already have a
  canonical identifier tests the input label, which can never match. So it walks those nodes again, and
  each walk labels their neighbours in traversal order. A self-referencing blank node is also counted
  twice. Ordinary credentials are affected: two licences that each hold an unnamed `{"code": "US"}`,
  or same-looking items with different children. The W3C `rdf-canon` suite has no such case and every
  W3C vector was unaffected, which is how this went unnoticed.

  Over 120 such credentials, 1.5.0 verified 53 of the reference `eddsa-rdfc-2022` implementation's
  proofs and refused 67 as invalid signatures, and the reverse direction failed alike. This version
  verifies all 120, and the reference verifies all 120 of ours; bbs-2023 cross-verifies on the same
  shape in both directions. It affects `eddsa-rdfc-2022`, `ecdsa-rdfc-2019`, `bbs-2023` and the Legacy
  RDFC variant. JCS, JOSE, COSE and SD-JWT never used it. A mismatch always failed closed: canonical
  output is a relabeling of the input, so two different datasets never signed the same bytes.

  `RdfcDocumentCanonicalizer` now runs on `Rdfc10Canonicalizer`, an internal copy of dotNetRDF's class
  with the defects fixed, until an upstream release does. `tests/fixtures/generated/rdfc-differential.json`
  pins 1,870 datasets byte for byte against `rdf-canonize` 5.0.0, and `RdfCanonicalizationDeviationTests`
  reports when dotNetRDF is fixed and the copy can go. No public API changes.

  **Wire change.** A document with blank nodes that tie at the first degree can now canonicalize to
  different bytes, so an RDFC proof made by 1.5.0 or earlier over such a document no longer verifies
  here. Those proofs did not verify on the reference implementation either, and conforming issuers'
  proofs of those documents now verify here. The Unicode ordering correction below can also change bytes without any tied blank nodes. Inventory affected stored proofs before upgrading. Only the original issuer or another explicitly
  authorized signer can reissue them; a verifier cannot repair third-party signatures. Coordinate
  issuer/holder/verifier upgrades, retain the original artifacts for audit, and request reissuance
  rather than silently falling back to the defective canonical form.

  The same work fixed five more defects in that class, found by adversarial review. Each was in 1.5.0
  except the last, which was introduced and fixed here:
  - **A hostile document could end the process.** A blank node with thousands of related nodes overflowed
    the stack, which cannot be caught: a 2.9 MB JSON-LD document killed a 1.5.0 verifier outright. Such a
    list is now refused before any permutation is tried, and recursion stops at 1,000 levels or when the
    stack runs low, so a long chain of blank nodes is a refusal too.
  - **A few hundred bytes could take minutes.** A permutation that recursed into nothing cost nothing,
    so a 500-byte N-Quads document ran past 30 seconds and 400 bytes of JSON-LD took 6.7 seconds. These now
    finish or are refused in about 50 ms. A node repeated across named graphs counts as one permutation.
  - **A predicate outside ASCII was hashed percent-encoded**, so tied blank nodes around it could be
    labelled differently from the specification. Such a predicate is now hashed as written.
  - **A document with more than 1,000 blank nodes could not be canonicalized at all**, because every node
    spent a budget of 1,000 walks. Only tied nodes are walked now. Formatting was also quadratic in blank
    nodes; 100,000 of them now take about two seconds, down from over a minute.
  - **The work budget.** Doing the walk correctly costs more on deep chains of like objects, so the budget
    is now 20,000 plus 4 per blank node, spent per walk, per related node and per permutation, with large
    issuer copies and long hashed strings charged too. A 2.3 MB hostile clique is refused in about half the
    time it took 1.5.0. At its default settings `rdf-canonize` refuses a 64-node chain that this accepts.

- **bbs-2023 proofs now interoperate with the reference implementation** (issue
  [#43](https://github.com/moisesja/dataproofs-dotnet/issues/43), found while reviewing #40). Through
  1.5.0 the suite's proofs verified only here: the W3C `derivedRevealDocument.json` vector did not
  verify (the test checked the CBOR framing only), and a reveal made here failed on the reference
  verifier. Four deviations from the specification's algorithms, all in `Bbs2023Cryptosuite`:
  the base proof signed every N-Quad as a BBS message where the spec signs only the non-mandatory
  ones (the mandatory ones are bound through the BBS header); the derived proof's mandatory and
  selective indexes were absolute positions in the full list where the spec's are relative (within the
  revealed N-Quads and within the non-mandatory messages); the reveal document was selected from the
  skolemized document, so it exposed `"@id": "urn:bnid:_:bN"` skolem IRIs where the spec selects it
  from the document as written and blank nodes stay blank; and the derived label map was keyed by
  skolem labels, with every key read back as `b<int>`, where the spec keys it by the reveal's
  canonical `c14n<int>` labels and the verifier canonicalizes the reveal as given. The last one is
  why an untampered reveal with an `@list` value never verified (#43): its list blank nodes had no
  skolem label and were lost in the label map.

  The suite now follows the reference algorithms (`@digitalbazaar/bbs-2023-cryptosuite` over
  `di-sd-primitives`), including the HMAC over the canonical labels. Verified: the W3C
  `derivedRevealDocument.json` verifies directly and through the pipeline; the base proof's BBS header
  equals `addHashData.json`; the derived proof's label map and relative indexes equal
  `derivedDisclosureData.json`/`derivedAdjIndexes.json` and the reveal equals
  `derivedUnsignedReveal.json`; and a reveal made here verifies on the reference verifier
  (`Bbs2023ConformanceTests`, plus an out-of-band run of the JavaScript stack). Verification no
  longer skolemizes the reveal, so the PR #37 vector where skolemization re-inserted a deleted `@id`
  is gone: the deleted member now changes the signed literal and the proof fails. The CBOR framing is
  unchanged, but **bbs-2023 proofs created by 1.5.0 do not verify with this version**, nor the other
  way round; 1.5.0's verified nowhere else either.

  Documents a `@list` value, or any other blank node the compact skolemizer cannot name, are now
  refused at creation and derivation with `JsonLdDataLossException` ("holds a blank node that
  bbs-2023 skolemization cannot name, such as a @list's") instead of failing at verification. The
  reference implementation cannot sign them either. A language map is refused with the skolemization
  message, as documented, instead of the language-tag one.

  `CreateBaseProofAsync` refuses an HMAC key that is not 32 bytes with `ProofGenerationException`
  before signing. The base proof parser requires that length, as the reference implementation does,
  so a proof issued with another could never be derived from. An invalid private key now also throws
  `ProofGenerationException`, where it used to throw `ArgumentException`.

  **Mandatory selection preserves the selected claim.** Creation and derivation reject nested
  document `@context` members before transformation, enforcing the selection algorithm's root-only
  precondition. This is conservative even for literal JSON data containing that key; scoped context
  definitions at the root remain supported. A subset check alone was insufficient: losing a nested
  context could rewrite a mandatory predicate into another statement already present in the document.
  Selection now densifies only arrays constructed while walking pointers, preserving real nulls in
  copied JSON literals. Previously, a mandatory `[null,1]` literal could become its signed sibling
  `[1]`, and a disclosure omitting the intended literal still verified. Real-BBS tests cover both
  failures and selective/mandatory literal preservation.

  **Derived proofs retain the base proof context.** A document's root context can change under
  RDF-preserving recompaction while its proof still needs its own context for signed extensions.
  Derivation copies the base proof and replaces `proofValue`; clearing that context returned a proof
  that could not verify. Contexts absent in reference fixtures remain absent; present ones are kept.

  **Blank-node labels are consumed as complete N-Quads tokens.** Labels such as `_:foo-bar`,
  `_:foo_bar` and `_:é` now issue, derive and verify; the prior ASCII-only token scanner truncated
  them and returned unusable disclosures.

- **bbs-2023 proofs over 4,096 characters work.** NetCid's default decode limit refused any longer
  `proofValue`, since 1.5.0, so a base proof with many mandatory pointers could not be derived from, and
  a derived proof with 87 or more undisclosed statements could not be verified. The limit is now
  1 MiB characters, about 22,000 undisclosed statements, and issuance and derivation refuse to produce
  anything longer, so a returned proof can always be parsed. Verification cost grows with the proof,
  genuine or not, to about 10 seconds at the limit as measured here, so the wire ceiling is not a service work budget. The BbsSelectiveDisclosure sample now demonstrates
  a 32 KiB body / 16 KiB proof / bounded JSON-shape profile with two concurrent verifications and
  no waiting queue. Tune admission to measured workload; hard deadlines require worker isolation.

### Known limitations

- **JSON-LD expansion in dotNetRDF is slow on long arrays.** One expansion of a document holding an
  8,000-item array takes about 13 seconds, and canonicalizing expands at least twice, so a 46 KB document
  can keep a verifier busy for 27 seconds. This happens before the canonicalizer's work budget applies.
  Nothing caps it yet; a service that verifies untrusted documents should limit their size.
- **Unicode interop boundary.** This version follows RDFC-1.0 code-point ordering, including
  first-degree hashing and BBS statement ordering. `rdf-canonize` 5.0.0 and earlier library versions
  use UTF-16 ordering. When supplementary characters compete with U+E000–U+FFFF characters, bytes
  can differ even without blank nodes. Old proofs over those datasets require issuer-driven
  reissuance; cross-verification with that oracle version is not claimed for those inputs.
- **bbs-2023 cannot disclose mandatory statements alone, nor secure a document whose every statement
  is mandatory.** The spec allows both (zero disclosed BBS messages, zero signed messages); NetCrypto
  1.7.1's BBS provider needs at least one revealed index and at least one message. Both are refused
  with `ProofGenerationException` naming the remedy: select at least one non-mandatory statement, or
  leave one. Lifting this needs a NetCrypto change.

## [1.5.0] - 2026-10-28

### Security

- **RDFC canonicalization fails closed when JSON-LD processing would drop or respell data**
  (issue [#36](https://github.com/moisesja/dataproofs-dotnet/issues/36)). `RdfcDocumentCanonicalizer`
  handed JSON-LD to dotNetRDF, which silently drops what it cannot turn into RDF and prints IRIs
  normalized. Whatever it dropped or respelled was not signed, so a holder could add or change it
  without breaking an RDFC proof. Each of these verified on 1.4.0:
  - changing a claim the contexts do not define. credentials/v2 has no `@vocab`, so this is every
    custom claim of a credential that lists only that context;
  - injecting a second `credentialSubject`, a `refreshService`, a nested node or a `type` entry whose
    IRI .NET does not consider well formed (`did:example:m[0]`, `?filter[id]=1`, `a#b#c`);
  - rewriting `issuer`, `validFrom` and `validUntil` when the credential's own `id` was such an IRI;
  - respelling an IRI (`/x/%2E%2E/users/alice` for `/users/alice`, `HTTPS://HOST` for `https://host`).

  The canonicalizer now rejects such input with the new `JsonLdDataLossException`. Creating a proof
  throws `ProofGenerationException` with it as the inner exception, and verification fails with the new
  `DATA_LOSS_DETECTION_ERROR`, as VC Data Integrity 1.0 §2.4.3 requires. It is rejected when:
  - it uses a term no `@context` defines, or a keyword-like member;
  - any IRI is not a well-formed absolute IRI: a subject, type, property, value, named-graph name,
    list member or datatype;
  - it has a malformed language tag or uses a blank node as a property;
  - it uses `@direction` or `@index`, which RDF canonicalization cannot carry. That includes an
    `@index` that expansion drops before any check sees it: a set object's (`{"@set": [...], "@index": "x"}`)
    or a null value's. Keyword aliases count, resolved by the JSON-LD processor itself (chains and scope
    included), and keys inside `@json` literals are data;
  - the canonical N-Quads would spell one of its IRIs differently: dot segments, percent-encoded
    unreserved or non-ASCII characters, upper-case scheme or host, a default port;
  - it resolves a relative IRI against an `@base`. dotNetRDF resolves with `System.Uri`, which respells
    the IRI during expansion, so `users/%61lice` would sign as `users/alice`. A `@base` that resolves
    nothing passes, and so does a `"@base"` key that is data inside a `@json` literal;
  - two distinct RDF terms would merge in dotNetRDF's store, which compares parsed URI components.
    For example, a subject `https://e.example/` appended next to a signed `https://e.example` lost its
    statements and still verified. A statement could likewise be moved into a graph named
    `https://g.example/` beside a signed `https://g.example`. Exact duplicate statements stay harmless;
  - a `@base` takes effect in a scoped context that a loaded context defines (dotNetRDF honors these,
    though it ignores a remote context's own `@base`);
  - a language tag is not ASCII letters, digits and hyphens: `en\n` passed dotNetRDF's pattern and put
    a line break into the quad;
  - a number is beyond the double range: `1e400` and `2e400` both signed as `Infinity`;
  - the JSON's meaning is unpredictable under RFC 8259: an unpaired-surrogate escape (read as U+FFFD),
    a duplicate member name (the last one won), invalid UTF-8, or nesting past 64. The suites already
    refused these; `CanonicalizeJsonLd` called directly now does too, with `RdfCanonicalizationException`.
    N-Quads input with an unpaired surrogate is refused as well.

  The parse itself is unchanged, so accepted input canonicalizes to exactly the bytes it did before,
  and every W3C vector passes unchanged. Messages name the cause and never quote the input.
  Affected: `eddsa-rdfc-2022`, `ecdsa-rdfc-2019`, `bbs-2023` and the Legacy RDFC variant. The JCS suites,
  JOSE, COSE and SD-JWT never used JSON-LD processing.
- **bbs-2023: a holder could change a disclosed literal without breaking the derived proof.**
  Blank-node relabeling and deskolemization rewrote text across whole N-Quad lines, literals included.
  So a literal `<urn:bnid:_:b0>` reached the signature as `_:b0`, and a reveal carrying `_:b0` instead
  still verified. A literal `_:c14n0` did not verify at all. Both now rewrite only blank-node and IRI
  terms.

  Creating and deriving also refuse a document that already uses the `urn:bnid:` namespace bbs-2023
  reserves for its blank-node ids, checked on the canonical form, so compact IRIs count.

  Creating, deriving **and verifying** refuse a document that skolemization would change. Skolemization
  works on compact JSON, and it added an `@id` to `@json` values and `@id` maps, which the reveal
  document then showed. The check also runs on the holder's reveal. Before, a holder could delete an
  `@id` member from a signed `@json` value: verification's skolemization re-inserted it, recreating
  the signed bytes, and the deletion still verified. Now it fails with `DATA_LOSS_DETECTION_ERROR`.
- **The Legacy RDFC variant left its proof configuration largely unsigned** under credentials/v2
  alone. That context does not define `Ed25519Signature2020` or `EcdsaSecp256r1Signature2019`, so
  `created`, `proofPurpose`, `verificationMethod`, `challenge` and `domain` were dropped from the
  signed bytes. That left proof purpose and replay binding unprotected. It is now refused (see Changed).
- **RDFC proofs over credentials/v1 documents left their proof configuration largely unsigned** when
  the document did not also list `https://w3id.org/security/data-integrity/v2`. credentials/v1 does
  not define `DataIntegrityProof`, so `cryptosuite`, `proofPurpose`, `verificationMethod` and the rest
  were dropped. It is now refused. The W3C vectors list that context, so they were never affected.

### Added

- `JsonLdDataLossException` (Rdfc), derived from `RdfCanonicalizationException`, which is no longer
  `sealed`.
- `ProofProblemCodes.DataLossDetectionError` (`DATA_LOSS_DETECTION_ERROR`, Core).
- Two contexts in `OfflineDocumentLoader`, each pinned to a byte-identical upstream commit:
  - `https://www.w3.org/ns/credentials/undefined-terms/v2`: VCDM 2.0 §5.2 asks a credential with terms
    no context defines to list it last, and it makes those terms signable;
  - `https://w3id.org/security/suites/ed25519-2020/v1`: the `Ed25519Signature2020` proof terms.

### Changed

- **Behavioral change: RDFC accept-set narrowing.** Documents that signed and verified under 1.4.0
  now fail when JSON-LD processing would drop or respell part of them. That includes proofs this
  library created over such documents. To upgrade:
  - define your terms in a context, or list `https://www.w3.org/ns/credentials/undefined-terms/v2`
    last in `@context`;
  - write IRIs well formed, absolute (not resolved against an `@base`), in normalized form, and keep
    distinct IRIs from differing only in an empty path (`https://host` vs `https://host/`);
  - for a credentials/v1 document, also list `https://w3id.org/security/data-integrity/v2` (bundled);
  - for the Legacy RDFC variant, list `https://w3id.org/security/suites/ed25519-2020/v1`
    (`Ed25519Signature2020`), or supply a context that defines the `EcdsaSecp256r1Signature2019`
    terms (none is published);
  - give RDFC proof options only extension members the context defines.

  **Interop note:** dotNetRDF's IRI test is stricter than jsonld.js's. Brackets in a query and non-BMP
  characters, for example, are refused here, where jsonld.js would sign them.
- `CanonicalizeNQuads` and `CanonicalizeNQuadsToMap` reject an IRI the canonical form would respell.
- `bbs-2023` verification reports data loss as `DATA_LOSS_DETECTION_ERROR`, where it used to report
  "Verification failed unexpectedly".
- Each JSON-LD canonicalization now runs one extra JSON-LD expansion for the checks: up to about
  1 ms more for a typical credential on a developer laptop.

### Known limitations

- **Not treated as data loss.** JSON-LD expansion discards these before any check can see them, and
  they carry no statements, so this is the same in every JSON-LD processor:
  - `null` values;
  - top-level values, and nodes that carry nothing but an `@id`.

  Some values have several spellings that sign the same: numbers are signed in the canonical XSD form
  the JSON-LD-to-RDF algorithm defines (`1` and `1.0` sign the same), and dotNetRDF lower-cases language
  tags, which BCP 47 compares case-insensitively.
- **bbs-2023 cannot yet sign** `@json` values without an `@id` member, container maps (language, `@id`,
  `@type`) or keyword aliases. Its skolemization works on compact JSON, so for these it refuses rather
  than alter the data. A `@json` value that already carries an `@id` member is signed as written. The fix is the expanded-form skolemization the spec describes
  ([#38](https://github.com/moisesja/dataproofs-dotnet/issues/38)).
- The Legacy suites' verification keeps its dual-variant result codes. A data-loss failure of the RDFC
  variant fails closed, but it is reported as `PROOF_VERIFICATION_ERROR` or `PROOF_TRANSFORMATION_ERROR`.
- The COSE lossy-UTF-8 limitation listed under 1.4.0 remains open
  ([#31](https://github.com/moisesja/dataproofs-dotnet/issues/31)).

### Why this is a minor and not a patch

This release adds public API: a new exception type, a new problem code, and an exception type
unsealed, all source-compatible. Its accept-set narrowing also rejects input that is valid JSON-LD.
An undefined term is legal JSON-LD that every processor silently drops. VCDM 2.0 makes such a
credential non-conforming, and VC Data Integrity requires the error. Under the versioning policy in
[`RELEASING.md`](RELEASING.md), each alone is minor material, and the narrowing also rejects this
library's own earlier output.

## [1.4.0] - 2026-10-27

### Added

- **Native AOT and trimming support** (issue [#27](https://github.com/moisesja/dataproofs-dotnet/issues/27)). All six packages declare `IsAotCompatible` and
  build with zero trim, single-file and AOT analyzer warnings, which the repo-wide warnings-as-errors
  makes fatal. Every System.Text.Json (de)serialization in the packages goes through source-generated
  metadata, from one internal `JsonSerializerContext` in each package that serializes JSON: Core, Jose,
  Rdfc and Legacy (Cose and the DI package serialize none). Between them they cover `DataIntegrityProof`,
  `JsonObject`, `JsonNode`, `JsonElement`, the JWS and JWE protected headers, `Jwk` and `string`.
  **Emitted bytes are unchanged.** Member order, null omission, escaping and extension-data placement
  are pinned by reflection-versus-source-generation identity tests in Core and Jose, and every
  conformance, vector and cross-stack byte-identity suite passes unchanged.
- **CI job `ac-12` proves it at run time.** `tasks/aot-smoke` exercises every package: Data Integrity
  with the JCS, RDFC and `bbs-2023` suites and a proof chain; both legacy suites in their JCS and RDFC
  variants; JWS, JWT, JWE, SD-JWT with Key Binding, COSE_Sign1, CWT and VC-JOSE-COSE; RDFC
  canonicalization through the offline loader; JWK conversion; `AddDataProofs`; and a consumer
  `JsonSerializerContext` that lists `DataIntegrityProof`. The job runs it four ways on linux-x64:
  under JIT; under JIT with reflection-based serialization disabled, the serializer condition of a
  trimmed host; as a .NET 10 file-based app (`dotnet run app.cs`, which applies the native-AOT defaults);
  and as a native-AOT binary. The deterministic outputs must be byte-identical across all four, and the
  randomized artifacts are verified across runtimes. The job also fails on any `IL2xxx`/`IL3xxx` warning
  in the native publish that is not on a reviewed list of known, unreachable third-party warnings,
  whichever assembly it names, and on a log that lacks the tool's own canary warning, which proves the
  analysis ran and was not suppressed. The RDFC canonicalizer (dotNetRdf.Core and its Newtonsoft.Json
  dependency) was shown to work under native AOT in the issue; the job keeps proving it. Unblocks
  [moisesja/zcap-dotnet#154](https://github.com/moisesja/zcap-dotnet/issues/154).
- **The JCS suites no longer depend on reflection inside NetCid.** `ac-12`'s first reflection-disabled
  run found that NetCid's `JcsCanonicalizer.Canonicalize(JsonNode)` overloads serialize the node through
  reflection-based System.Text.Json. NetCid carries no trim or AOT annotations, so the analyzers that
  build the packages could not see it. Only the ILCompiler's whole-program analysis of an application
  reports it, as a warning attributed to NetCid. `eddsa-jcs-2022` and `ecdsa-jcs-2019` verification
  called that overload whenever the proof carries `@context`, which these suites copy from the
  document's `@context`, so every proof over a JSON-LD document carries one. In a trimmed or native-AOT
  host every such verification therefore failed closed, as
  `PROOF_VERIFICATION_ERROR: Verification failed unexpectedly (InvalidOperationException)`. A JIT host
  with reflection-based serialization enabled, the default, was not affected. The suite now
  canonicalizes a `JsonElement`; the canonical bytes are unchanged, as the W3C vector suites confirm.
  `BannedSymbols.txt` bans the four `JsonNode` overloads, so the build fails if one is reintroduced.
- **Publishing `Rdfc` with native AOT: Newtonsoft.Json warnings.** An application that native-AOT
  publishes `DataProofsDotnet.Rdfc`, or `Legacy` or the DI package, which reference it, gets trim and AOT
  warnings from Newtonsoft.Json, dotNetRdf.Core's dependency, for its `dynamic` support, which
  dotNetRdf's JSON-LD parser never reaches. They are collapsed into `IL2104` and `IL3053` for that
  assembly. Under `TreatWarningsAsErrors` they fail the publish. To keep them visible but not fatal,
  without relaxing your own code's analyzers, add:

  ```xml
  <WarningsNotAsErrors>$(WarningsNotAsErrors);IL2104;IL3053</WarningsNotAsErrors>
  ```

  This makes **every** dependency's collapsed trim and AOT warnings non-fatal, not only
  Newtonsoft.Json's. Hidden reflection in another dependency would then publish and fail at run time, so
  check that each `IL2104`/`IL3053` in the publish log names `Newtonsoft.Json` and nothing else.
  Applications that use only Core, Jose and Cose see no IL warnings.

### Changed

- **NetCrypto dependency raised from 1.4.0 to 1.7.1**, the latest stable release on NuGet as of
  2026-10-27. All packages now inherit the 1.7.1 minimum transitively. The update requires no source
  migration here; the full tests, samples and four-runtime AOT parity gates pass with the new package.

- **`DataProofsJsonOptions.Default` resolves this library's types through source-generated metadata
  first** (issue [#27](https://github.com/moisesja/dataproofs-dotnet/issues/27)). Its resolver chain is the Core context followed by the reflection resolver. The
  reflection resolver is added only when `JsonSerializer.IsReflectionEnabledByDefault` is true, which it
  is in an ordinary JIT application, so JIT consumers' own types serialize as before. Trimmed and
  native-AOT builds, and any project that sets `PublishAot` (the SDK turns the switch off there even
  under `dotnet run`), default the switch to false. There, a consumer type without source-generated
  metadata now fails with System.Text.Json's `NotSupportedException` naming the type. Register such
  types in your own `JsonSerializerContext`; `DataIntegrityProof` can be listed there directly. A host
  that opts back in with `JsonSerializerIsReflectionEnabledByDefault=true` keeps the fallback for its own
  types; the library's types never use it.
- **Observable to JIT consumers, without changing any bytes:** `Default.TypeInfoResolver` and
  `TypeInfoResolverChain` now hold the source-generated context (and the reflection resolver), and a
  `JsonException` from a malformed proof can carry a different message and byte position (for example,
  a non-string `cryptosuite` is now reported against `DataIntegrityProof` rather than `System.String`).
  Exception types are unchanged.
- **`DataIntegrityProof.Type` and `DataIntegrityProof.AdditionalProperties` are settable** (`set`
  instead of `init`). The .NET 10 source generator models `init`-only members as constructor
  parameters. An `init`-only extension-data bag is rejected at first use, and an `init`-only member with
  an initializer loses its default when the member is absent from the payload, which would have turned
  the `Type` of a proof without a `type` member from `"DataIntegrityProof"` into `null`.
  Source-compatible: object initializers and `with` expressions compile unchanged. **Not
  binary-compatible:** an `init` accessor's signature carries `modreq(IsExternalInit)` and a `set`
  accessor's does not, so an already-compiled dependent fails with `MissingMethodException` on
  `set_Type` or `set_AdditionalProperties` until it is rebuilt. Binary compatibility is out of scope per
  `RELEASING.md`; this is the migration step. ZcapLd.Core 4.2.0 and 5.0.0 and ZcapLd.AspNetCore 5.0.0
  reference neither setter.
- **`PreviousProofReferenceJsonConverter` is public** (it was internal). It is still applied through
  the `[JsonConverter]` attribute on `PreviousProofReference` and never needs registering. It is public
  so that a consumer can list `DataIntegrityProof` in its own `JsonSerializerContext`, which the source
  generator refuses (SYSLIB1220) when the converter is inaccessible. `System.Type`, from its `Read`
  signature, joins the AC-7 BCL allowlist with that justification.
- **A secured document whose JSON cannot be read is one document-level `PROOF_TRANSFORMATION_ERROR`**
  (issue [#33](https://github.com/moisesja/dataproofs-dotnet/issues/33); see **Fixed**).
  `DataIntegrityProofPipeline.Verify` and `VerifyAsync` now check the document before parsing any proof
  or calling the resolver. A document that fails the check returns `Verified = false`, an empty
  `ProofResults` and a single entry in `Problems`, for example `PROOF_TRANSFORMATION_ERROR: The secured
  document has a duplicate member name.` Some of these documents already failed before, but per proof,
  after the resolver had been called. They failed as `PROOF_TRANSFORMATION_ERROR`, as "The proof could not
  be parsed." or as "Verification failed unexpectedly", depending on where the content sat; others threw.
  A caller that reads only `ProofResults` must also read `Problems`, or `Verified`.
- Pre-existing and unchanged, now written down: `JweBuilder` renders the General JSON serialization with
  the default HTML-safe encoder (an unprotected `kid` containing `+` is emitted as `\u002B`), while
  `JwsBuilder` uses the relaxed encoder. The anonymous-type rendering, which source generation cannot
  describe, was replaced by a `JsonObject` with the same member order and escaping, pinned by a test.

### Fixed

- **A JWS protected header that is not valid UTF-8 is now rejected on every entry point** (issue
  [#28](https://github.com/moisesja/dataproofs-dotnet/issues/28)). RFC 7515 §5.2 step 3 requires
  the verifier to check that the base64url-decoded header "is a UTF-8-encoded representation of a
  completely valid JSON object". Nothing did. `JwsParser.Parse` happened to reject a member *name*
  that was not UTF-8 — a side effect of enumerating member names for the §5.2 step 4 disjointness
  check — but `JwsParser.ParseCompact` and `VcJose.VerifyCredential` skip that enumeration and
  verified the same signed header, and a non-UTF-8 string *value* in an extension member verified
  on all three. The decoded octets are now validated once, before JSON parsing, in the shared
  decode path, so compact, Flattened, General, detached, and VC-JOSE all fail as
  `MalformedJoseException` ("… is not valid UTF-8") before key resolution. The compact path's
  no-enumeration performance choice is unchanged.

  **Accept-set note.** Every newly rejected header was already invalid under RFC 7515 §5.2 step 3.
  No header this library emits is affected: `JwsBuilder` and `VcJose` serialize headers from .NET
  strings, which encode only to valid UTF-8. Only a signer that hand-assembles a malformed header
  is affected.

- **The same UTF-8 check now guards every other decoder in the package — two of which were
  reachable before any signature check.** Found while tracing #28 to its root cause; none of these
  were in the report.

  | Decoder | Before 1.4.0 | Reachable before a signature check? |
  | --- | --- | --- |
  | SD-JWT issuer JWT and Key Binding JWT header/payload (`CompactJwt`) | A non-UTF-8 member name threw a raw `InvalidOperationException` out of `SdJwtVerifier.Verify` and the Key Binding check, both documented as never throwing. | **Yes** — step 1 of the verifier. |
  | SD-JWT Disclosure (`Disclosure.Parse`, via `SdJwtComponents.Parse`) | A non-UTF-8 claim name threw a raw `InvalidOperationException` out of `SdJwtVerifier.Verify`; a non-UTF-8 array-element value was accepted. | **Yes** — Disclosures are presented by the holder and parsed in step 1. |
  | JWT claims set (`JwtClaims.Parse`) | A non-UTF-8 claim name or registered string claim threw a raw `InvalidOperationException`, through `JwtHandler.Verify`'s never-throws promise; a non-UTF-8 unregistered string value was accepted. | After the signature via `JwtHandler`; directly, through the public `Parse`. |
  | JWE protected header (`JweProtectedHeader.Decode`) | A non-UTF-8 member name was accepted with the name replaced by U+FFFD; a non-UTF-8 extension string value was accepted. | Before decryption. A tampered header fails the AEAD tag, so only an envelope its sender built with this header could have been accepted. |

  All four now fail as `MalformedJoseException` ("… is not valid UTF-8"). The structured-result APIs
  translate that into a failure result: `MALFORMED` from `SdJwtVerifier.Verify` and
  `JwtHandler.Verify`, and `KB_JWT_MALFORMED` from the Key Binding check. The governing text is:

  - RFC 7515 §5.2 step 3 and RFC 7519 §7.2 step 10 for the SD-JWT issuer and Key Binding JWTs.
  - RFC 9901 §4.2.1 and §4.2.2 for Disclosures.
  - RFC 7519 §7.2 step 10 for the JWT claims set.
  - RFC 7516 §5.2 step 3 for the JWE protected header.

  **Upgrade note: one kind of this library's own output is now rejected.** `JwsBuilder` signs a
  caller-supplied payload as-is, without checking its encoding. A JWT built that way, with a
  non-UTF-8 string in an *unregistered* claim, passed 1.3.x `JwtHandler.Verify`. 1.4.0 rejects it
  with `MALFORMED: JWT claims set is not valid UTF-8.` A non-UTF-8 claim *name* or registered claim
  already threw in 1.3.x. Such a token was never valid under RFC 7519 §7.2 step 10, and
  `JwtHandler.SignAsync` cannot produce one, because it serializes claims from .NET strings. SD-JWT
  issuance, Key Binding JWTs and Disclosures are serialized the same way and are unaffected.
  `VcJose.VerifyCredential` returns the credential bytes opaquely, as before.

  One layer up, a .NET string that is not well-formed UTF-16 (a lone surrogate) handed to
  `JwsParser.Parse` or `JweParser.Parse` made `JsonDocument.Parse` throw `ArgumentException`
  through the same contract; it now fails as `MalformedJoseException` too. That input cannot arise
  from decoding wire bytes with .NET — invalid sequences become U+FFFD — only from a caller's own
  text. A JSON *escape* for a lone surrogate, such as `\uD800`, is a different case: it is plain
  ASCII on the wire. It is fixed in the next entry.

- **A JSON escape for an unpaired surrogate is now rejected by every JOSE decoder, and two more
  exception-contract escapes are closed** (issue
  [#30](https://github.com/moisesja/dataproofs-dotnet/issues/30)). The adversarial review of the
  #28 fix found all three; all three predate this release.

  1. **Unpaired-surrogate escapes** (`\uD800`, `\uDC00`, `\uD800A`). Those bytes are valid UTF-8,
     so the #28 check passed them, and RFC 8259 §8.2 lets the JSON grammar contain them. The string
     they denote is not Unicode text, though: RFC 8259 §8.2 calls the receiver's behaviour
     "unpredictable" and RFC 7493 (I-JSON) §2.1 forbids it. System.Text.Json accepts the escape at
     parse time and throws `InvalidOperationException` when the string, or a member name it
     compares, is first read. Before this fix:
     - **Before any signature check**, that exception escaped `SdJwtVerifier.Verify` and
       `SdJwtVcVerifier.VerifyAsync` (the issuer JWT's header or payload, or any presented
       Disclosure), `JwsParser.Parse` (any member of the JSON serialization, even one it never
       reads), `JweParser.Parse`, `PeekRecipients` and `ParseAsync` (likewise), and
       `VcJose.VerifyCredential` (`cty`), as well as `JwtClaims.Parse` and `Disclosure.Parse`
       directly.
     - **After a valid signature**, it escaped the Key Binding check (`typ`, `aud`, `sd_hash`,
       `nonce`), SD-JWT payload reconstruction (`_sd` digests, `...` placeholders), the `cnf` key
       read, and `JwtHandler.Verify` (`iss`, `sub`, `jti`, `aud`, any claim name).
     - **Where nothing read it, it was accepted:** in an extension member of a JWS or JWE protected
       header, an unread member of a JWS or JWE JSON serialization, a Disclosure value, or an
       unregistered JWT claim. A signed JWT carrying one in an unregistered claim passed
       `JwtHandler.Verify` with `IsValid == true`, and the consumer's own read of
       `AdditionalClaims`, `ToJsonString()` or `ToJsonBytes()` then threw.

     Every JSON text the package parses on receipt is now checked before it is parsed: the JWS and
     JWE protected headers, the JWS and JWE JSON serializations, the JWT claims set, the SD-JWT
     issuer and Key Binding JWTs, and every Disclosure. For the JSON serializations the check has to
     precede the parse: `JsonDocument`'s own duplicate-member check transcodes member names and
     throws the same `InvalidOperationException`. One reader pass validates the UTF-8 and transcodes
     each escaped string and member name. A failure is `MalformedJoseException`
     ("… contains an unpaired UTF-16 surrogate escape."), which the structured-result APIs report
     as `MALFORMED` or `KB_JWT_MALFORMED`. Well-formed escapes, a surrogate *pair* included, read
     back unchanged.
  2. **`JwtClaims.Parse` with a non-object root** (`[]`, `42`, `"x"`, `true`) threw
     `InvalidOperationException`, including through `JwtHandler.Verify` on a validly signed token.
     It now fails as `MalformedJoseException` ("JWT claims set is not a JSON object."), as `null`
     already did.
  3. **`JweParser` with `"protected": ""`** threw `ArgumentException` from `Parse`,
     `PeekRecipients` and `ParseAsync`, before any key work. It now fails as
     `MalformedJoseException` ("JWE protected header is empty."), as the JWS parser already did.
  4. **Two JWE key-agreement escapes**, found by the adversarial review of this fix and also older
     than this release:
     - A small-order X25519 `epk`, or ECDH-1PU sender key, gives the all-zero shared secret, which
       RFC 7748 §6.1 lets a party reject. NetCrypto rejects it with `CryptographicException`, and
       the key derivation sat outside every catch, so it escaped `Parse`, `ParseAsync`,
       `ParseCompact` and `ParseCompactAsync`. No key is needed to send one. It is now the uniform
       decrypt failure (`JoseCryptoException`, "JWE could not be decrypted.", no inner exception),
       identical whether or not the recipient key is held, so the issue #12 constant-work property is
       unchanged. The same catch also reports a recipient private key of the wrong length, which
       threw `ArgumentException` before, as the uniform failure. On `Parse` that exception had come
       only from a held key, so closing it removes a possession signal under misconfiguration. On
       `ParseCompact`, `ParseCompactAsync` and `ParseAsync`, which use the caller's own key, the
       caller sees the generic message rather than the length. `IEcdhKey.DeriveAsync` now documents
       that a keystore-backed implementation should report key-agreement failures as
       `CryptographicException`, because any other type propagates unchanged and would tell a held
       key from the decoy.
     - An ECDH-1PU sender key that the caller's resolver returns off-curve or malformed (in
       DIDComm, from the sender's own DID document) threw `CryptographicException` or
       `ArgumentException`. It is now `JoseCryptoException` ("ECDH-1PU sender public key for skid
       '…' is malformed or not on its curve."), as a malformed `epk` already was. An OKP sender key
       whose `x` has the wrong length still fails as `MalformedJoseException`, as before.
     - `ParseCompact` with a caller key on a signing-only curve (Ed25519, secp256k1), met by an
       `epk` on the same curve, threw `NotSupportedException`. It is now `JoseCryptoException`
       ("Recipient key curve '…' is not supported for key agreement."). `Parse` was never affected,
       because it substitutes a decoy for such a key.

  **Accept-set note: this narrowing rejects input the JSON grammar allows.** Unlike the #28
  octets, an unpaired-surrogate escape is valid RFC 8259 grammar; I-JSON forbids it, but neither
  the JSON nor the JOSE RFCs do. Under [`RELEASING.md`](RELEASING.md) that makes it minor
  material, which 1.4.0 already is. No JSON this library serializes itself contains one:
  `JwtHandler.SignAsync`, the headers `JwsBuilder` and `JweBuilder` write, `SdJwtIssuer` and
  `KeyBindingJwt.IssueAsync` serialize .NET strings and caller-built JSON nodes. System.Text.Json
  writes a lone surrogate in a .NET string as U+FFFD, a pre-existing substitution this release
  does not change, and throws on a node parsed from text that carries the escape, so neither
  reaches the output. The only output of this library that 1.4.0 newly rejects is a JWT, or an
  SD-JWT issuer JWT, whose payload bytes the caller handed to `JwsBuilder` as-is, carrying such an
  escape in a claim nothing validates. It passed 1.3.x `JwtHandler.Verify` (or `SdJwtVerifier.Verify`
  and `SdJwtVcVerifier.VerifyAsync`) and threw when the claim was read. 1.4.0 rejects it as
  `MALFORMED: … contains an unpaired UTF-16 surrogate escape.` Caller bytes that
  `VcJose.EnvelopeCredentialAsync` and `JweBuilder` carry are unaffected: `VcJose.VerifyCredential`,
  `JwsParser` and `JweParser` return payloads and plaintexts opaquely, without parsing them.

  The regression suite covers each placement above on each entry point named, with four escapes
  (`\uD800`, `\uDC00`, `\uD800A`, `\uD800\uD800`), plus the key-agreement cases: 816 cases in
  all. Every case that feeds one of these inputs fails against the pre-fix code. The ones that
  pass on both are the over-rejection guards, which prove that well-formed escapes (a surrogate
  pair included) and this library's own non-BMP output still verify, their controls, and the
  `null`-root case, which already failed correctly.

- **The Data Integrity pipeline checks the JSON it is given before reading it, and keeps its
  contracts for JSON it cannot process** (issue
  [#33](https://github.com/moisesja/dataproofs-dotnet/issues/33)). `DataIntegrityProofPipeline.Verify`
  and `VerifyAsync` are documented never to throw for an invalid document. `AddProofAsync` is documented
  to throw `ProofGenerationException` for an invalid document or invalid options. Four kinds of JSON broke
  both contracts:

  - a JSON escape for an unpaired UTF-16 surrogate (`\uD800`);
  - a member name repeated in one object;
  - text that is not valid UTF-8;
  - nesting deeper than 64 levels.

  System.Text.Json accepts all four into a `JsonElement` and fails only when a later step reads the
  content. So the exception, and the step that threw it, depended on where the content sat.

  - A `\uD800` member name threw `InvalidOperationException` out of `Verify` and `VerifyAsync` before any
    signature check. So did a non-UTF-8 member name, and a `\uD800` in the `id` of a proof that
    `previousProof` references.
  - `AddProofAsync` threw `InvalidOperationException`, `JsonException` or `ArgumentException`.

  No forged proof verified: every case failed closed. But a verifier that relied on the documented
  result-only contract, with no catch-all, crashed on one crafted document.

  Every Data Integrity entry point that takes a document now makes one pass over its UTF-8 first. The pass
  rejects all four. Member names are compared after unescaping, so `"a"` and its escaped spelling are the
  same name; names that differ only in case are distinct. Comments and trailing commas left in a leniently
  parsed element are not faults. Some later steps re-parse raw text strictly (proof embedding, bbs-2023
  skolemization), so an element carrying either is replaced by a strict copy of the same JSON before any
  step reads it. The pass keeps one member-name set per nesting depth, reused across sibling objects, so a
  document of many small objects allocates almost nothing for it.

  - `Verify` and `VerifyAsync` report a failing document as one document-level
    `PROOF_TRANSFORMATION_ERROR`, before any proof is parsed and before the resolver is called (see
    **Changed**). The message names the fault and quotes no content: "The secured document has a
    duplicate member name."
  - `AddProofAsync` throws `ProofGenerationException`: "The document to secure contains a JSON escape for
    an unpaired UTF-16 surrogate." It also checks the proof options. Their raw JSON (`@context` and
    extension members) is checked as given, because serialization would rewrite non-UTF-8 text as U+FFFD
    or throw. Extension keys matching any modeled proof member are rejected, including omitted members:
    "The proof options object has an extension member with a reserved proof name." Their serialized
    form is checked too, against the depth it will occupy in the secured document: one level below the
    root, or two once the proof member is an array. That check runs before the suite signs, so no
    signature is spent on a document that could not be written out: "The proof options object nests deeper
    than 63 levels."
  - The pipeline's own transformation steps also map any remaining System.Text.Json fault to the contract.
    On verification that is a failed result; on creation it is `ProofGenerationException` with the cause
    attached. Two such faults are reachable today. On creation, a document at the 64-level limit whose
    object-form proof becomes an array element when a second proof is added fails as "The secured
    document could not be assembled." One case still fails after signing, so the signature is spent and
    discarded. Most suites copy the document's `@context` into the proof, where it sits one level deeper
    than in the document. A `@context` already nested to the 64-level limit therefore cannot be written
    out. The pipeline does not check for it before signing, because it cannot know whether the suite
    copies `@context`: the legacy JCS suites don't, and a pre-check would reject documents they can sign.
    A real `@context` is a list of URLs or a small object, so this takes a deliberately pathological
    document. On verification, a proof
    whose `previousProof` names itself is re-embedded one level deeper. At the limit it fails with the
    fixed message "The secured document could not be transformed for verification." The call into the
    suite is not wrapped, so a signer's exceptions keep their types.

- **The same check guards the suites' own create entry points.** They are public and documented to throw
  only `ProofGenerationException` for invalid input. None of them was in the report.

  | Entry point | Before 1.4.0 |
  | --- | --- |
  | `CreateProofAsync` of every suite: `eddsa-jcs-2022`, `ecdsa-jcs-2019`, `eddsa-rdfc-2022`, `ecdsa-rdfc-2019`, and `Ed25519Signature2020` and `EcdsaSecp256r1Signature2019` in both variants | Proof options whose `@context` or extension members held an unpaired-surrogate escape threw a raw `JsonException`. A `default(JsonElement)` there threw `InvalidOperationException`. An extension member named like a modelled one (`proofPurpose`) was written twice. The JCS suites then refused the configuration; the others signed a proof carrying both members. |
  | The legacy suites' `CreateProofAsync`, JCS variant | A hostile document threw a raw `InvalidOperationException`, `JsonException` or `ArgumentException`. A nested duplicate was signed, with the last value winning. Non-UTF-8 text was signed as U+FFFD. |
  | The RDFC suites, and the legacy suites' RDFC variant | Duplicate members and unpaired-surrogate escapes were signed: the JSON-LD processor silently picked a value. Non-UTF-8 text threw a raw `InvalidOperationException`. |
  | `Bbs2023Cryptosuite.CreateBaseProofAsync` and `DeriveProof` | Every kind threw a raw exception (`InvalidOperationException`, `JsonException`, `ArgumentException` or `JsonReaderException`), except one: `DeriveProof` accepted a non-UTF-8 string value. `CreateBaseProofAsync` also threw a raw `JsonReaderException` for a document with a comment or a trailing comma. `DeriveProof` is the holder's boundary over a document an issuer sent. It also threw raw exceptions for a malformed base proof. A modelled member of the wrong JSON kind threw `JsonException`, and a `proofValue` that is not the five-element CBOR array threw `InvalidOperationException`. A public key or signature of the wrong size threw `ArgumentException`, a signature that does not match its messages threw `CryptographicException`, and an invalid mandatory or selective JSON pointer threw `ArgumentException`. So did a disclosure that reveals no statement: a base proof without mandatory pointers, derived with a selection that is empty or matches nothing. |

  They now throw `ProofGenerationException`, with "The document to secure …", "The secured base document
  …" (`DeriveProof`) or "The proof configuration …". A malformed base proof in `DeriveProof` fails as
  "The base proof could not be parsed.", "The base proofValue is not a valid bbs-2023 base proof.", "The
  base proof's BBS signature could not be used to derive a proof.", "The base proof carries an invalid
  mandatory pointer.", "A selective pointer is invalid." or "The selective disclosure reveals no
  statements.". A mandatory-only disclosure (an empty selection over a base proof with mandatory
  pointers) still derives. `BbsUnavailableException` still escapes as documented. Rdfc and Legacy carry a verbatim copy of the internal check, so neither reaches into Core's
  internals. The suites' `VerifyProof` methods already failed closed, and are unchanged.

  **PR #35 review follow-up.** A configuration at depth 64 can become depth 65 when the legacy JCS
  suites nest it under the document's `proof` member. These transformation failures now throw
  `ProofGenerationException` with the JSON exception attached; signer faults remain outside the mapping.
  Regression tests cover both legacy JCS suites, direct calls and the pipeline, the successful depth-64
  combined document, and signer exception identity.

  Extension keys now cannot match **any** modeled proof JSON name, even when its typed property is null
  or omitted. Checking serialized configuration alone missed `AdditionalProperties["proofValue"]`:
  signing populated the typed field afterward, emitted two `proofValue` members and returned a document
  the verifier rejected. The check uses source-generated property metadata in all three packages.
  Shared tests cover all modeled names across all eight suite create paths and BBS creation, with
  pipeline regressions and controls for case-sensitive and nested extension names.

  **Upgrade note.** A caller that caught `InvalidOperationException`, `JsonException` or
  `ArgumentException` from any method above now gets `ProofGenerationException`, or, from `Verify` and
  `VerifyAsync`, a failed result.

  **Creation-options migration.** Populate modeled fields through their typed properties; reserve
  `AdditionalProperties` for unmodeled extensions. An extension with a modeled name is now rejected
  even if it previously serialized as a single member because its typed property was omitted. This is
  an additional creation-input narrowing for every suite, including JCS; it does not newly reject
  well-formed earlier wire proofs, whose modeled members deserialize into typed properties.

  **Accept-set note.** What this narrows depends on the suite.

  - **`eddsa-jcs-2022` and `ecdsa-jcs-2019`.** Their canonicalizer already refused duplicates, unpaired
    surrogates and depth beyond 64. RFC 8785 requires this: "JSON objects MUST NOT exhibit duplicate
    property names" (§3.1), and a lone surrogate "MUST cause a compliant JCS implementation to terminate
    with an appropriate error" (§3.2.2.2). For these the exception type and the result shape change; the
    accept-set does not.
  - **Non-UTF-8 text.** Through `AddProofAsync` it used to be signed, for every suite, after the
    serializer had rewritten it as U+FFFD, so the secured document differed from the caller's. Called
    directly, the suites refused it, threw, or (the legacy JCS variant) signed it the same way. It is now
    rejected everywhere. RFC 8259 §8.1 requires UTF-8.
  - **The RDFC suites and the legacy suites' RDFC variant** newly reject duplicate member names and
    unpaired-surrogate escapes, which they used to sign. **The legacy JCS variant** newly rejects nested
    duplicates, which it signed with the last value winning. RFC 8259 admits both: names "SHOULD be
    unique" (§4), and the receiver's behaviour is "unpredictable" (§4, §8.2). I-JSON (RFC 7493 §2.1, §2.3)
    forbids both. Under `RELEASING.md` this is a spec-valid narrowing.

  **This library's own earlier output is among what is now rejected.** Before this release,
  `eddsa-rdfc-2022`, `ecdsa-rdfc-2019` and the legacy suites signed caller input that carried a nested
  duplicate member, and `AddProofAsync` kept the duplicate in the secured document. Such a document now
  fails verification with `PROOF_TRANSFORMATION_ERROR`. Re-issue it from deduplicated input. The same
  suites also signed proof options whose extension member repeated a modelled name, and the proof they
  emitted carried both members. That proof is now rejected the same way. Earlier output made from
  non-UTF-8 input carries U+FFFD instead, and still verifies.

  The regression suites run each placement above on each entry point named, with the same four escapes as
  #30.

  - A shared pipeline matrix runs through `eddsa-jcs-2022` and `eddsa-rdfc-2022`.
  - A shared create matrix runs through all eight suite create paths.
  - Separate matrices cover `bbs-2023`.

  In the original pre-review regression run against the pre-fix code, 625 cases failed. The 44 that passed are over-rejection guards, controls, and unit
  tests of the check itself. The guards prove that well-formed escapes, comments and trailing commas,
  depth 64, a name repeated across sibling objects, and proof chains still sign and verify.

### Known limitations

The JOSE decoders now hold their never-throws and `MalformedJoseException` contracts for the four
input classes this release's reviews found: invalid decoded octets (#28), unpaired-surrogate
escapes, non-object JWT claims roots and an empty JWE `protected` member (#30). The Data Integrity
entry points hold theirs for the four input classes of #33: unpaired-surrogate escapes, duplicate
member names, invalid UTF-8 and nesting past 64 levels. Each is pinned by tests on every entry point
named above. That is a statement about those input classes, not proof that the contracts hold for
every input.

Separately, the COSE package has the CBOR counterpart of this release's JWE fix. It reads text
strings in `CborConformanceMode.Lax`, which decodes a non-UTF-8 text string lossily, with U+FFFD
substitution, instead of rejecting it (RFC 8949 §3.1). `VcCose.Verify` still fails closed on its
fixed `typ` and content-type values, and no exception escapes; a text string that is not compared to
a constant is accepted. Tracked in [#31](https://github.com/moisesja/dataproofs-dotnet/issues/31).

### Security

- **`Microsoft.SourceLink.GitHub` lifted 10.0.300 → 10.0.403** (build-time only, referenced with
  `PrivateAssets="All"`; nothing ships to consumers). 10.0.300 pulled `Microsoft.Build.Tasks.Git`
  10.0.300, which the newly published
  [GHSA-23fw-v26w-5fgq](https://github.com/advisories/GHSA-23fw-v26w-5fgq) (CVE-2026-62900, .NET
  information disclosure, patched in 10.0.303) covers, so the repo-wide NuGet audit (`NU1902` as
  error) failed every restore — including the last CI run on `main` before this release.
  Supply-chain hygiene only; no runtime code path changes.

### Why this is a minor and not a patch

Per the versioning policy in [`RELEASING.md`](RELEASING.md), an accept-set narrowing whose every
newly rejected input was already invalid ships as a patch, and the UTF-8 narrowing (#28) qualifies:
no public API changed, no emitted bytes changed, and every newly rejected input was invalid under
its RFC. That includes the one kind of this library's own output now rejected, described in the
upgrade note above. It is a minor by the owner's decision, because the narrowing spans four
decoders at once. On the SD-JWT issuer JWT, Key Binding JWT and Disclosure paths, it also replaces
a raw `InvalidOperationException` escaping a never-throws API with a structured failure, for this
input class. A consumer could have been depending on that behaviour, however wrongly, through a
catch-all. The version number is there to make that consumer read this entry. Recorded as a worked
example in `RELEASING.md`. The unpaired-surrogate narrowing (#30) does not qualify for a patch at
all: the escapes it rejects are valid RFC 8259 grammar, forbidden only by I-JSON, so by the policy's
own terms it is minor material. So is the Data Integrity narrowing (#33) for the RDFC and legacy suites,
which signed duplicate member names and unpaired-surrogate escapes that RFC 8259 admits; it also rejects
the two kinds of this library's own earlier output named above. The native-AOT work in this release is minor material on its own: a feature,
two public members loosened from `init` to `set` and one type made public — all source-compatible — and
a change to `DataProofsJsonOptions.Default`'s resolution of consumer types, which a consumer's own types
observe only in hosts that disable reflection-based serialization.

## [1.3.0] - 2026-08-05

### Added

- **`JwsKidPlacement` — the signer `kid` can now travel in the per-signature unprotected header**
  (issue [#25](https://github.com/moisesja/dataproofs-dotnet/issues/25)). `JwsSigner` takes an
  optional third constructor argument, `JwsKidPlacement kidPlacement = JwsKidPlacement.Auto`, and
  exposes it as a `KidPlacement` property:

  | Value | Effect |
  | --- | --- |
  | `Auto` (default) | The placement the declared media type needs — see below. |
  | `Protected` | Always the integrity-protected header (the 1.2.x behavior), every serialization. |
  | `Unprotected` | Always the per-signature unprotected `header`. JSON serializations only. |

  Under `Auto`, a JSON-serialized JWS whose `typ` is the DIDComm signed media type —
  `application/didcomm-signed+json`, or the bare `didcomm-signed+json`, since DIDComm v2.1
  §Message Formats permits omitting the `application/` prefix — emits
  `protected = {typ, alg}` plus `header = {kid}`. Every other media type keeps the `kid` in the
  protected header, and compact serialization always does: RFC 7515 §7.1 gives it no unprotected
  header to use. `BuildCompactAsync` throws `ArgumentException` when a signer explicitly requests
  `Unprotected`, rather than silently signing a `kid` the caller asked to leave unsigned.

### Fixed

- **DIDComm v2.1 signed envelopes are interoperable again.** 1.2.0 fixed a genuine RFC 7515 §7.2.1
  violation (the `kid` was emitted in *both* headers) by making it protected-only — the
  conservative placement, but not the one DIDComm uses. Every signed envelope in DIDComm v2.1
  Appendix C.2, and every envelope emitted by the two SICPA reference implementations, carries
  `protected = {typ, alg}` with `header = {kid}`. With the `kid` protected-only, outbound signed
  interop for `moisesja/didcomm-dotnet` went from **1-of-2** reference implementations accepting
  our envelopes to **0-of-2**:

  - didcomm-jvm 0.3.2 — `MalformedMessageException: JWS Unprotected Per-Signature header must be
    present` (`Unpack.kt:63`).
  - didcomm-python 0.3.2 — `core/validation.py` requires `signatures[0].header.kid`, and
    `core/sign.py` reads it unconditionally without consulting the protected header.

  Because `Auto` keys off the media type, a consumer producing DIDComm signed messages is fixed by
  the version bump alone — no code change.

- **A single-signer DIDComm signed envelope now uses the General JSON serialization**, not the
  Flattened one. This is a *second* blocker, found while verifying the fix above against
  didcomm-python's source and not identified in issue #25. `unpack_sign` in `didcomm/core/sign.py`
  (v0.3.2) calls `validate_jws` on the **raw** envelope dict, and `didcomm/core/validation.py`
  rejects anything without a `signatures` array — before authlib is ever asked to normalize the
  serialization. So a Flattened envelope fails there with `MalformedMessageError` no matter where
  the `kid` sits, and the `kid` fix alone would have left didcomm-python interop broken at 1-of-2.
  didcomm-jvm is unaffected either way, since nimbus-jose-jwt normalizes both forms.

  DIDComm v2.1 §Message Signing allows either form and requires recipients to process both, so
  this is an interop accommodation rather than a conformance fix — which is why it is scoped to
  the DIDComm signed media type. Every other JSON JWS still flattens for a single signer, and the
  General form is still selected automatically for two or more signers as before.

  With both changes, a freshly built envelope is structurally identical to the authoritative
  DIDComm v2.1 spec vectors — same root members, same `signatures` array, same protected member
  set, same unprotected `header` — for all three of their algorithms (EdDSA, ES256, ES256K).

### Wire-format delta

Emitted bytes change **only** for a JSON-serialized JWS whose `typ` is the DIDComm signed media
type. For that shape, two things change: a single-signer envelope is rendered General
(`{payload, signatures:[…]}`) instead of Flattened, and — for a kid-bearing signer — `kid` moves
out of the base64url `protected` header into a per-signature `header` member, which also changes
the signing input and therefore the signature bytes.

Everything else is byte-identical to 1.2.1: compact JWS, JWT, SD-JWT, SD-JWT VC, VC-JOSE-COSE, and
every other `typ` in either serialization — including the RFC 7520 cookbook `json_flat`
byte-compare and the frozen `tests/fixtures/generated/es256k-jws.json` vector, both of which are
unchanged and still pass.

There is nothing to do on the verify side: `JwsParser` has read the unprotected `kid` first with a
protected-header fallback since [#10](https://github.com/moisesja/dataproofs-dotnet/issues/10), so
it accepts both placements, and it has enforced RFC 7515 §5.2 step 4 disjointness since
[#19](https://github.com/moisesja/dataproofs-dotnet/issues/19). A consumer that reads the signer
`kid` straight out of DIDComm envelope JSON must now look in the per-signature `header`;
`JwsParseResult.SignerKid` resolves either placement and always has.

**Interop matrix for DIDComm signed envelopes.** A 1.3.0 verifier accepts output from 1.2.0, 1.2.1,
and 1.3.0 (but still not from ≤ 1.1.1, whose both-headers shape RFC 7515 §5.2 step 4 requires
rejecting — unchanged from 1.2.1). A 1.2.x verifier accepts 1.3.0's output too, since the
unprotected-kid path is exactly what #10 added. The peers that could not read 1.2.x output are the
external ones — didcomm-jvm and didcomm-python — and 1.3.0 is what fixes them.

### Migration note — recompilation required for the `JwsSigner` constructor

Source-compatible, **not binary-compatible**. `JwsSigner..ctor(ISigner, string)` is replaced by
`JwsSigner..ctor(ISigner, string, JwsKidPlacement)`; an optional parameter does not preserve the
old CLR method token, so an already-compiled dependent that was built against 1.2.x throws
`MissingMethodException` if the 1.3.0 assembly is dropped in without a rebuild. No source change is
needed — recompile against 1.3.0 and existing call sites bind to the new default. This is accepted
under this repository's policy (binary compatibility is not a release constraint; downstream is
rebuilt), and is recorded here because it is a real migration step, not a compatibility guarantee.

### Why this is a minor and not a major release

Per the versioning policy in [`RELEASING.md`](RELEASING.md). The public .NET API change is
**source-additive** — an optional constructor parameter, two get-only properties, and a new enum —
so `ac-7` stays green and no existing call site changes. It is *not* binary-additive; see the
migration note above, which that policy classifies as a rebuild step rather than a major bump
because binary compatibility is explicitly out of scope for this project. The emitted-output change is confined to the DIDComm
signed media type, where the previous bytes were rejected by both reference implementations, so no
conformant DIDComm peer could have been relying on them. It is a minor rather than a patch
precisely because the wire changed for that media type.

### Security note — read this if you consume `JwsParseResult.SignerKid`

RFC 7515 §6 is the governing text, and its condition is load-bearing: "These Header Parameters MUST
be integrity protected **if** the information that they convey is to be utilized in a trust
decision; however, **if the only information used in the trust decision is a key**, these parameters
need not be integrity protected, since changing them in a way that causes a different key to be used
will cause the validation to fail."

**As a key hint, an unprotected `kid` is sound.** It selects a key; the signature is then verified
under that key; a rewritten `kid` resolves a key the attacker cannot sign under, so verification
fails. `SignerKid` is reported only *after* a successful verify (the reasoning recorded in #10).

**As a signer identity, it is not.** That safety argument holds only while the caller's
`Func<string, Jwk?>` resolver is injective, and nothing requires it to be. An adversarial review of
this change demonstrated the gap concretely: when one DID document lists the same key under two
verification-method ids — an entirely ordinary arrangement, e.g. `#key-1` in `authentication` and
`#assert-1` in `assertionMethod` — an intermediary can rewrite the unprotected `kid` from one to the
other. The signature still verifies, and `SignerKid` reports the attacker's choice. A verifier that
derives a proof purpose, a verification relationship, or an authorization scope from `SignerKid` is
making a trust decision on an unsigned value. The same rewrite against a protected `kid` is refused
outright, because adding an unprotected `kid` beside a protected one breaks RFC 7515 §5.2 step 4
disjointness (#19). A pinned-key or single-key resolver has the same exposure in a stronger form.

Two things ship to address it:

- **`JwsParseResult.SignerKidIsProtected`** (new) — `true` when the protected header carried a
  `kid` **member**, so the signature covers it. It is `false` for the unprotected placement *and*
  when no `kid` was carried at all, so `if (!result.SignerKidIsProtected) reject;` fails closed.
  Before this, a verifier had no way to tell the two placements apart, which made
  `JwsKidPlacement.Protected` a mitigation only the *producer* could apply. The flag reports
  member presence rather than value emptiness: RFC 7515 §4.1.4 requires `kid` to be a string, not a
  non-empty one, so a signed `"kid":""` is valid and is correctly reported as protected.
- **The `SignerKid` documentation itself now carries the qualification**, not just
  `SignerKidIsProtected`. The previous text — and the corresponding parser comment — asserted that
  a forged `kid` "resolves a different key and fails to verify", which is exactly the claim this
  release's own regression test disproves. `SignerKid`, `SignerKidIsProtected`,
  `JwsKidPlacement.Unprotected`, and the inline parser rationale now agree: when
  `SignerKidIsProtected` is `false`, `SignerKid` is the key-selection hint that resolved the
  verifying key and nothing more.
- **The XML docs no longer claim DIDComm *requires* the unprotected placement.** It does not; RFC
  7515 §4.1.4 and DIDComm v2.1 both leave placement open. What drives `Auto` is DIDComm's published
  Appendix C.2 examples and reference-implementation interoperability, and the docs now say so.

The exposure follows from the unprotected *placement*, not from DIDComm conformance — DIDComm v2.1
states no placement rule, so an implementation using a protected `kid` is equally conformant and
does not carry it. What makes it near-universal in practice is that the Appendix C.2 examples and
both reference implementations use the unprotected header, so interoperating implementations
converge on that shape. This library's parser has accepted unprotected-kid envelopes from peers
since #10; what changed in 1.3.0 is that our own DIDComm output now has the property too. Callers
who need the signer identity bound into the signed bytes should pass `JwsKidPlacement.Protected`,
which remains the default for every non-DIDComm media type.

### Also fixed in this release (found by the adversarial review, not by issue #25)

- **A non-string `kid` in the *protected* header no longer escapes the parser's exception
  contract.** `{"alg":"EdDSA","kid":null}` deserialized a `null` onto the header model, and
  `JwsParser` passes the `kid` to the caller's resolver *outside* its `try` block — so a resolver
  that dereferenced the argument threw `NullReferenceException`, and a dictionary-backed one threw
  `ArgumentNullException`, straight through the documented
  `MalformedJoseException`/`JoseCryptoException` contract. Any caller's
  `catch (MalformedJoseException)` was bypassed, giving a remote unauthenticated crash on
  attacker-supplied input. The protected header now rejects a present-but-non-string `kid` per
  RFC 7515 §4.1.4, before key resolution — the protected-header half of the check
  `ReadUnprotectedKid` has performed since #15. This narrows the accept-set only for input that was
  already invalid.
- **A protected header whose JSON root is not an object, or whose member name is not valid UTF-8,
  now also fails as `MalformedJoseException`.** `JsonElement`'s member accessors
  (`TryGetProperty`, `EnumerateObject`) throw `InvalidOperationException`, not `JsonException`, in
  those cases. The invalid-UTF-8 variant escaped `JwsParser.Parse` before this release; the
  non-object-root variant was introduced *by* the `kid` check above and caught by a second
  adversarial pass before it shipped. Both now route through the documented contract on all three
  entry points — `JwsParser.Parse`, `JwsParser.ParseCompact`, and `VcJose.VerifyCredential`.

  > **Correction (2026-10-26, issue [#28](https://github.com/moisesja/dataproofs-dotnet/issues/28)).**
  > The invalid-UTF-8 half of this claim was wrong for two of the three entry points. In 1.3.0
  > only `JwsParser.Parse` rejected a non-UTF-8 member name; `ParseCompact` and
  > `VcJose.VerifyCredential` accepted and verified the same signed header, because the rejection
  > was a side effect of member-name enumeration that the compact path skips, not a UTF-8 check. A
  > non-UTF-8 extension *value* was accepted on all three. No test covered the input class on any
  > entry point. Fixed in 1.4.0.
- **The unprotected `header` is now written with the same JSON encoder as the protected one.**
  `JsonObject.ToJsonString()` defaulted to HTML-escaping while `DeterministicJsonWriter` uses
  `JoseJson.Default`'s relaxed encoder, so one envelope could render the same `kid` two ways —
  `did:x#a+b` as `a+b` protected but `a+b` unprotected. Both parse identically; the
  inconsistency was cosmetic but is the kind that breaks byte-comparison against other
  implementations' vectors.
- **Documentation correction.** `BuildCompactAsync`'s and `JwsKidPlacement.Unprotected`'s XML docs
  said compact rejects a signer requesting `Unprotected`, unconditionally. It rejects one that
  requests `Unprotected` *and carries a `kid`*; a kid-less signer has nothing to place and is
  accepted. The behavior was correct and matched `JwsSigner`'s own doc; the other two were wrong.

## [1.2.1] - 2026-08-04

### Fixed

- **`JwsParser` now rejects non-disjoint protected and unprotected JWS headers** (issue #19).
  RFC 7515 §5.2 step 4 requires the two parameter-name sets to have no members in common,
  regardless of whether duplicate values match. Both Flattened and General JSON serializations
  now enumerate the complete raw header namespaces and throw `MalformedJoseException` before key
  resolution or signature verification when any name overlaps — including `kid`, `alg`, or an
  extension parameter. The former special case that accepted a matching `kid` in both headers has
  been removed. Conformant protected-only and unprotected-only `kid` forms remain valid; the latter
  still resolves and reports the verified signer as required for DIDComm v2.1 (issue #10). No public
  API or emitted-wire change; this tightens only the parser's accept-set to match strict verifiers.
  Adjacent structural hardening now also rejects mixed Flattened+General objects, a present
  unprotected `header` that is not a JSON object, and an empty protected-header string through the
  parser's documented `MalformedJoseException` contract.

  **Upgrade note — this rejects envelopes produced by DataProofsDotnet ≤ 1.1.1.** Those versions
  emitted the signer `kid` in *both* headers (the bug fixed in 1.2.0), which is exactly the shape
  1.2.1 now refuses. A 1.2.1 verifier therefore cannot verify a signed envelope from a peer still
  running ≤ 1.1.1. In a mixed deployment, upgrade **senders** to ≥ 1.2.0 — whose output is
  conformant and verifies on every version — rather than expecting 1.2.1 to keep accepting the old
  shape; no version of this library will accept it again, since RFC 7515 §5.2 step 4 requires the
  rejection. Downstream coordination for DIDComm is tracked in
  [`moisesja/didcomm-dotnet#70`](https://github.com/moisesja/didcomm-dotnet/issues/70).

  Shipping as a **patch** under the accept-set clause of the versioning policy in
  [`RELEASING.md`](RELEASING.md): no public .NET API change (`ac-7` green), no emitted-output
  change, and every newly-rejected input was invalid under RFC 7515 — strict verifiers such as
  nimbus-jose-jwt were already rejecting it, so no conformant peer could have produced it.

### Changed

- **Bumped the `NetCrypto` dependency from 1.1.0 to 1.4.0** across all packages. The intervening
  releases add deterministic asymmetric-key zeroization, public EC point decompression, and the
  `IRecoverableDigestSigner` abstraction for HSM/key-store EVM signing. This library requires no
  source migration; consumers now resolve NetCrypto ≥ 1.4.0 transitively.

## [1.2.0] - 2026-08-04

### Fixed

- **`JwsBuilder` no longer duplicates the signer `kid` in both the protected and unprotected
  JWS headers** (issue #17). Both JSON serializations (Flattened and General) rendered a
  per-signature unprotected `"header": {"kid": ...}` object carrying the same `kid` already
  stamped into the integrity-protected header, violating RFC 7515 §7.2's requirement that the
  two header parameter-name sets be disjoint. Strict verifiers enforce this — nimbus-jose-jwt
  (used by didcomm-jvm) rejected every such JWS, blocking DIDComm v2.1 live-interop for the
  `signed` and `anoncrypt(sign)` compositions downstream. The `kid` is now **protected-only**
  (the conservative placement: it stays under the signature, and it is where `JwsParser` has
  preferred to read it since #10); the unprotected `header` object is no longer emitted at all.
  Round-trip behavior is unchanged — `JwsParser` already falls back to the protected header's
  `kid` when no unprotected one is present. Regression tests pin protected/unprotected
  parameter-set disjointness for both serializations. Wire-format note for consumers that
  inspected the envelope JSON directly: single- and multi-signature outputs with a kid-bearing
  signer no longer contain a `header` member (kid-less output is byte-identical to before).
  **Why this is a minor and not a major release:** the public .NET API is unchanged, and the
  removed member was part of an RFC 7515-invalid envelope that strict verifiers were already
  rejecting, so no conformant consumer could have depended on it — see the versioning policy in
  [`RELEASING.md`](RELEASING.md). A consumer that reads the signer `kid` straight out of the
  envelope JSON must read it from the protected header (or use `JwsParseResult.SignerKid`, which
  has always resolved both placements). Downstream impact is tracked in
  [`moisesja/didcomm-dotnet#70`](https://github.com/moisesja/didcomm-dotnet/issues/70).

### Known limitations

- **`JwsParser` does not yet enforce RFC 7515 §5.2 step 4 header disjointness on the verify side**
  ([#19](https://github.com/moisesja/dataproofs-dotnet/issues/19)). This release fixes what the
  library *emits*; it still *accepts* a JWS carrying the same `kid` in both headers, and never
  inspects the unprotected header for any other overlapping parameter. No signature-acceptance
  risk — the protected header stays authoritative for `alg`/`crit`/`b64` — but our accept-set is
  looser than what strict verifiers will grant us. Tracked for a follow-up release.

## [1.1.1] - 2026-07-27

### Added

- **Samples now cover the opaque-key (HSM / KMS / keychain) JWE flow** — a new section in
  `samples/DataProofsDotnet.Samples.Jwe` exercising `IEcdhKey`, the shipped `RawEcdhKey` handle, a
  worked custom `IEcdhKey` implementation standing in for a device-backed key, and the async
  `JweBuilder.BuildEcdh1PuA256KwAsync` / `JweParser.ParseAsync` / `JweParser.ParseCompactAsync`
  overloads. These eight public members shipped in **1.1.0** (issue #13) with no sample, which left
  the **`ac-9` samples-coverage gate (FR-21 / AC-9) red on `main`** and blocked the release
  checklist's "all AC gates green" precondition. Coverage is back to **100%** (540/540 public
  members, 0 allowlisted). The sample also demonstrates that ECDH-1PU invokes the handle **twice**
  per decrypt (`Ze` against the ephemeral, then `Zs` against the sender's static key).

### Security

- **Transitive `AngleSharp` lifted 1.4.0 → 1.6.0** (via a direct floor-lift reference in
  `DataProofsDotnet.Rdfc`, the sole `dotNetRdf.Core` consumer) to clear the newly published
  [GHSA-pgww-w46g-26qg](https://github.com/advisories/GHSA-pgww-w46g-26qg) mXSS advisory
  (< 1.5.0), which failed the repo-wide NuGet audit (`NU1902` as error) and blocked every
  restore. Supply-chain hygiene only: this stack never parses HTML — AngleSharp rides in for
  dotNetRDF's HTML/RDFa readers, which DataProofs does not use. Remove the floor-lift when
  dotNetRdf.Core's own AngleSharp floor reaches 1.5.0+.

### Fixed

- **`JwsParser` now rejects a non-string unprotected `header.kid` as `MalformedJoseException`
  instead of leaking a raw `InvalidOperationException`** (issue #15). Both raw-signature
  enumeration sites (Flattened and General JSON serializations) read the unprotected header's
  `kid` with `JsonElement.GetString()` without a `ValueKind` guard, so a JWS carrying
  `"header": {"kid": 123}` (or an object/array/boolean) escaped the parser as an untyped fault —
  bypassing every `catch (MalformedJoseException)` in consumers. This was reachable
  **pre-authentication**: the read happens during structural enumeration, before any signature
  check, so any peer able to deliver bytes could throw it (downstream, a single crafted message
  tore down a didcomm-dotnet WebSocket receive loop — `didcomm-dotnet#58`). The strict option
  was chosen: any present non-string `kid` — including JSON `null` — is malformed per RFC 7515
  §4.1.4. It now throws
  `MalformedJoseException("JWS unprotected header 'kid' must be a string.")`; silently ignoring it
  would hide a broken sender. An absent unprotected `kid` still falls back to the protected
  header's `kid`, and a valid string `kid` behaves as before.
  Severity is availability/robustness — no signature is accepted, no key material is exposed.
- **`JwsParser` now wraps the top-level `JsonDocument.Parse` so malformed JSON surfaces as
  `MalformedJoseException`** (issue #15, adversarial follow-up). The JSON-serialization entry point
  parsed attacker-supplied bytes without a `catch`, so a truncated frame, trailing junk, a duplicate
  member, or over-deep nesting escaped `JwsParser.Parse` as a raw `System.Text.Json.JsonException` —
  the same "untyped fault escapes pre-verification" failure class as the `kid` bug above, and more
  reachable (any partial WebSocket frame is malformed JSON). `JweParser.ParseStructure` and
  `JwtClaims.Parse` already wrap this call; `JwsParser` now matches them, throwing
  `MalformedJoseException("JWS is not valid JSON.")`.

## [1.1.0] - 2026-06-22

### Security

- **`JweParser.Parse` is now constant-work with respect to recipient-key possession** (issue #12).
  Previously the parser fast-failed **before any ECDH** when no recipient `kid` matched a held
  private key, so "key held" vs "key not held" was observable as a response-time difference — a
  **recipient-key enumeration oracle** for any consumer that decrypts attacker-supplied JWEs and
  exposes a timing-observable result (the root cause of downstream `didcomm-dotnet#35`). The parser
  now routes the non-decryptable case through a per-process **decoy** ECDH key on the envelope's
  work curve, performing the same key-agreement / key-unwrap work and then failing uniformly at
  unwrap. The decision keys on *"is a held key present that matches the envelope's `epk` curve?"* —
  not merely *"is the `kid` held?"* — which also closes a residual leak where a held key on the
  **wrong curve** fast-failed before the ECDH. Decoy keys are generated **once per process and
  cached** (a per-call key generation would itself re-introduce a timing signal). The successful
  decrypt path of a curve-matching held key is unchanged and pays nothing extra. **No public API
  change.**
  - **Scope:** this makes the parser's *own* post-resolution path constant-work for a fixed
    `(alg, enc, epk-curve)`. A fully constant-time decrypt additionally requires the supplied
    `IJweRecipientKeyResolver` (`FindPresent`/`TryGet`) to be timing-independent of which kids are
    held — that contract is outside the parser and remains the caller's responsibility.

### Added

- **Async `IEcdhKey` seam for opaque (HSM/keystore) ECDH keys** (issue #13). A new additive
  `IEcdhKey` handle (`Crv` + `DeriveAsync`) lets the JWE key-agreement step run on a private key
  that **never exposes its scalar** — HSM, cloud KMS, OS keychain, or `NetCrypto.IKeyStore` — while
  `DataProofsDotnet.Jose` stays DID-agnostic (the handle carries only a curve and a derive
  callback). New async overloads `JweParser.ParseAsync` / `ParseCompactAsync` (recipient supplied as
  an `IEcdhKey`) and `JweBuilder.BuildEcdh1PuA256KwAsync` (opaque sender static key; the per-message
  ephemeral stays raw) drive full **authcrypt (ECDH-1PU)** and **anoncrypt (ECDH-ES)** flows. The
  shipped `RawEcdhKey` wraps in-process key bytes and reproduces the existing conformance vectors
  **byte-for-byte**; opaque implementations live downstream over `IKeyStore.DeriveSharedSecretAsync`
  (raw `Z`). The existing **synchronous JWE API is unchanged** (back-compat), and the new async path
  carries the same issue #12 constant-work decoy defense.

## [1.0.1] - 2026-06-16

### Fixed

- **`JwsParser` now reports the verified signer `kid` when it is carried only in the JWS
  unprotected header** (issue #10). The parser already resolves the verifying key from the
  per-signature unprotected `header.kid` and verifies against it, but previously returned
  `JwsParseResult.SignerKid == ""` whenever the integrity-protected header carried no `kid` —
  discarding the `kid` that selected the verifying key. `SignerKid` is now the `kid` that resolved
  the key under which the signature verified (the protected header is preferred when present;
  otherwise the unprotected `kid` is reported). This is sound because verification has already
  succeeded: a rewritten unprotected `kid` resolves a different key under which the signature
  cannot verify, so a forged `kid` never reaches the result. This corrects an over-conservative
  decision from the issue #6 hardening pass (Finding #2) and unblocks **DIDComm Messaging v2.1**
  signed and `authcrypt(sign(...))` conformance, which places the signer `kid` in the unprotected
  JWS header (the five Appendix C.2/C.3 interop vectors that previously failed). Unchanged:
  a `kid` in the protected header is still reported as before, and a JWS whose protected and
  unprotected `kid` **disagree** is still rejected (`MalformedJoseException`).

  > **Correction (2026-08-05, issue #25).** The security reasoning above is **wrong**, and is left
  > in place rather than rewritten because it is what readers acted on. Two claims do not hold:
  > that the reported `kid` is "the identity the signature proved", and that "a rewritten
  > unprotected `kid` resolves a different key … so a forged `kid` never reaches the result".
  > Both assume the caller's `Func<string, Jwk?>` resolver is **injective**, which nothing in this
  > library requires. When two identifiers resolve the same key material — a resolver pinned to a
  > single key, or an ordinary DID document listing one key under both an `authentication` and an
  > `assertionMethod` verification-method id — an intermediary can rewrite the unprotected `kid`
  > to the other identifier, the signature still verifies, and `SignerKid` reports the attacker's
  > choice. The behavior 1.0.1 introduced is correct and stays: an unprotected `kid` is a valid
  > **key-selection hint** and reporting it is right. What was overstated is its status as an
  > authenticated **identity**. Since 1.3.0, `JwsParseResult.SignerKidIsProtected` distinguishes
  > the two cases; see that release's security note.

## [1.0.0] - 2026-06-14

### Added

- **`DataProofsDotnet.Legacy`** — a new opt-in package shipping the pre–Data-Integrity
  **Linked-Data-Signature** cryptosuites `Ed25519Signature2020` and
  `EcdsaSecp256r1Signature2019` (issue #7, FR-4). Each implements `ICryptosuite` and supports
  both a **JCS** variant (the back-compat default — the document with the proof nested under a
  `proof` member, JCS-canonicalized once) and an **RDFC-1.0** variant
  (`SHA-256(RDFC(proofOptions)) ‖ SHA-256(RDFC(document))`). The emitted proof carries
  `type:"<suite>"`, **no `cryptosuite`**, and a base58-btc `proofValue`; it create→verify
  round-trips through `DataIntegrityProofPipeline` (create dispatches by `cryptosuite` naming the
  suite; verify dispatches by `type` via `GetByProofType`). The suites are **not** registered in
  `CryptosuiteRegistry.CreateDefault()` — register them explicitly. The wire convention and
  signing bytes are **byte-identical to zcap-dotnet**, locked by a cross-stack golden vector
  (a zcap-issued `Ed25519Signature2020` proof verifies, and re-signing reproduces zcap's exact
  `proofValue`). Unmodeled proof members (e.g. `capabilityChain`) ride through
  `DataIntegrityProof.AdditionalProperties` into the JCS signing input. This unblocks
  zcap-dotnet's proof-pipeline delegation and legacy-VC verification in credentials-dotnet.
    - **Use legacy suites only for interop with existing corpora; prefer the 2022/2019 Data
      Integrity suites for new proofs.**
    - **Documented limitations** (verified by adversarial review): the JCS variant has no
      representation for a W3C proof chain and **fails closed** if asked to secure/verify a
      document that already carries a `proof` member (use the RDFC variant or a 2022/2019 suite
      for chains); the RDFC variant binds only terms defined in the active JSON-LD `@context`
      (members it does not define are dropped by RDF expansion — inherent to JSON-LD/RDFC, shared
      with the conformant `rdfc-*` suites); and `EcdsaSecp256r1Signature2019` does not enforce
      low-`s`, so ECDSA `proofValue`s are malleable and must not be used as unique identifiers.
- **JOSE explicit typing (RFC 8725 §3.11).** `JwtValidationOptions.ExpectedType` (opt-in) pins the
  JWS protected `typ` header on `JwtHandler.Verify` (case-insensitive, `application/`-prefix
  tolerant), rejecting cross-context token confusion; default behavior is unchanged. The verified
  `typ` is now surfaced on `JwsParseResult.Typ`.

### Changed

- **`Base64Url.Decode` is now strict (behavioral change).** It rejects any input outside the
  base64url-no-pad alphabet — including interior/surrounding ASCII whitespace, `=` padding, and the
  standard-base64 `+`/`/` — by throwing `FormatException`, where the previous implementation
  silently tolerated them. This matches the documented "valid base64url" contract and the JOSE
  no-pad requirement, but an out-of-repo caller that previously passed padded or whitespace-bearing
  input will now get a `FormatException`. **Upgraders:** scan your `Base64Url.Decode` call sites for
  non-canonical input. (Also tracked under Security below — it closes an encoding-ambiguity gap.)
- **Bumped the `NetCrypto` dependency from 1.0.0 to 1.1.0** across all packages. The library
  source is unaffected; consumers resolve NetCrypto ≥ 1.1.0 transitively. (1.1.0 also introduces a
  `NetCrypto.Base64Url` type — when a consumer imports both `NetCrypto` and `DataProofsDotnet.Jose`,
  reference `Base64Url` via a `using` alias or fully-qualified name to disambiguate it from
  `DataProofsDotnet.Jose.Base64Url`.)

### Security

- **JOSE hardening pass (issue #6).** An adversarial multi-agent review of the entire
  `DataProofsDotnet.Jose` surface (JWS/JWE/ECDH-1PU/JWK/SD-JWT/JWT/encoding), with every finding
  put through independent majority-vote verification, produced these fixes (each pinned by a
  regression test in `Hardening/HardeningRegressionTests.cs`):
    - **SD-JWT reconstruction now fails closed on a deep recursive-disclosure chain.**
      `SdJwtReconstructor` walked the disclosed payload by unbounded mutual recursion; a chained
      recursive-disclosure presentation (RFC 9901 §6.3) rooted in an issuer-signed `_sd` digest could
      drive it into an **uncatchable `StackOverflowException` that terminates the host process**,
      defeating the verifier's fail-closed contract. Reconstruction is now depth-bounded (64, matching
      the JSON parse depth) and raises a `MalformedJoseException` (surfaced as `DISCLOSURE_INVALID`).
    - **A malformed/unsupported `cnf` (or issuer) key no longer crashes SD-JWT verification.**
      `CompactJwt.Verify` mapped an unsupported curve / off-curve key point to an uncaught
      `NotSupportedException`/crypto exception (reachable through an attacker-influenced `cnf` on the
      Key Binding path); it now fails closed as `MalformedJoseException`, which both call sites handle.
    - **JWS reports the verified signer only from integrity-protected material.** `JwsParseResult
.SignerKid` is now sourced solely from the protected header; a `kid` carried only in the
      unauthenticated unprotected header is treated as a routing hint and never surfaced as the
      verified identity. Verification of valid JWS (including `kid`-in-unprotected) is unchanged.
    - **`Base64Url.Decode` is now strict** — it rejects interior/surrounding whitespace, `=` padding,
      and standard-base64 `+`/`/`, matching the documented base64url-no-pad contract.

## [0.1.0-preview.2] - 2026-06-13

### Added

- **`ICryptosuite.SupportedProofTypes`** — a default interface member (defaults to the single
  `DataIntegrityProof` type) by which a suite declares the proof `type`(s) it verifies. Existing
  suites are unaffected and continue to be dispatched by `cryptosuite` name.
- **`CryptosuiteRegistry.GetByProofType(string?)`** — resolves a legacy/type-named suite by its
  declared proof `type`, backed by a secondary `type → suite` index that excludes the default
  Data Integrity type (so the JCS suites stay unambiguous and name-dispatched).

### Fixed

- **Verify pipeline can now dispatch legacy / type-named proofs (issue #4, FR-4).** The verify
  path previously dispatched a proof to a cryptosuite only when it carried a `cryptosuite` member
  **and** `type == "DataIntegrityProof"`, making it impossible to register a suite that verifies
  pre–Data-Integrity Linked-Data-Signature proofs (`Ed25519Signature2020`,
  `EcdsaSecp256r1Signature2019`, …) — which name their algorithm by `type` and carry no
  `cryptosuite`. The pipeline could therefore emit (via a custom suite) a legacy-shaped proof it
  then refused to verify. Dispatch now falls back to the proof `type` when no `cryptosuite` is
  present (`cryptosuite`-named suites still always win), closing the create→verify inconsistency
  and honoring the FR-4 "registering a new suite requires no pipeline changes" contract. The
  library still **creates** only conformant 2022/2019 proofs; this is verification-only and
  non-breaking. Suite selection only _routes_ — each suite still fully validates
  `type`/`cryptosuite`/key/encoding/signature. Regression tests in
  `LegacyProofTypeVerificationTests` and `CryptosuiteRegistryTests`.

## [0.1.0-preview.1] - 2026-06-13

First preview release of all five packages (`Core`, `Jose`, `Cose`, `Rdfc`,
`Extensions.DependencyInjection`) — a NuGet prerelease for validation.

### Added

- **Repository scaffold**: five-package solution (`Core`, `Jose`, `Cose`, `Rdfc`,
  `Extensions.DependencyInjection`), central package management, PublicApiAnalyzers on every
  package from the first commit (FR-24), vendored conformance fixtures with provenance
  tracking, and CI per `dataproofs-prd.md` §9.

### Security

- **`bbs-2023` mandatory disclosure is now cryptographically enforced.** The mandatory-disclosure
  group is bound into the BBS signature `header` (`SHA-256(proofConfig) ‖ SHA-256(mandatory
N-Quads)`) at sign and derive, and the header is recomputed at verify from the revealed
  mandatory messages — so a holder that drops or alters a mandatory statement produces a header
  that no longer matches the one the proof commits to, and verification fails. Closes the
  adversarial-review finding that a holder could omit a mandatory claim and still verify. Requires
  NetCrypto ≥ 1.0.0 (the BBS `header` parameter, upstream moisesja/crypto-dotnet#2; first
  available in 1.0.0-preview.2, GA in 1.0.0); regression test
  `Verify_MandatoryStatementReclassifiedAsSelective_FailsClosed`.
