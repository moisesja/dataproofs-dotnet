# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-10-26

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

     Every JSON text the package decodes is now checked once, before it is parsed: the JWS and JWE
     protected headers, the JWS and JWE JSON serializations, the JWT claims set, the SD-JWT issuer
     and Key Binding JWTs, and every Disclosure. One reader pass validates the UTF-8 and transcodes
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

  **Accept-set note: this narrowing rejects input the JSON grammar allows.** Unlike the #28
  octets, an unpaired-surrogate escape is valid RFC 8259 grammar; I-JSON forbids it, but neither
  the JSON nor the JOSE RFCs do. Under [`RELEASING.md`](RELEASING.md) that makes it minor
  material, which 1.4.0 already is. No output this library serializes itself contains one:
  `JwtHandler.SignAsync`, the headers `JwsBuilder` and `JweBuilder` write, `SdJwtIssuer` and
  `KeyBindingJwt.IssueAsync` all serialize .NET strings, and System.Text.Json writes a lone
  surrogate as U+FFFD (a pre-existing substitution this release does not change). The one
  exception is payload bytes a caller hands to `JwsBuilder` as-is. A JWT built that way with such
  an escape in an unregistered claim passed 1.3.x `JwtHandler.Verify` and threw when the claim was
  read; 1.4.0 rejects it with `MALFORMED: JWT claims set contains an unpaired UTF-16 surrogate
  escape.` `JwsParser` and `VcJose.VerifyCredential` still return payload bytes opaquely, without
  parsing them.

  The regression suite covers each placement above on each entry point named, with four escapes
  (`\uD800`, `\uDC00`, `\uD800A`, `\uD800\uD800`), 674 cases in all; every negative case fails
  against the pre-fix code.

### Known limitations

The JOSE decoders now hold their never-throws and `MalformedJoseException` contracts for the four
input classes this release's reviews found: invalid decoded octets (#28), unpaired-surrogate
escapes, non-object JWT claims roots and an empty JWE `protected` member (#30). Each is pinned by
tests on every entry point named above. That is a statement about those input classes, not proof
that the contracts hold for every input.

The Data Integrity pipeline in Core has the same class of escape, found by the adversarial review
of the native-AOT work: an unpaired-surrogate escape in a member name throws
`InvalidOperationException` out of `DataIntegrityProofPipeline.Verify` before any signature check,
and malformed documents escape `AddProofAsync`'s `ProofGenerationException` contract. It predates
this release. Tracked in [#33](https://github.com/moisesja/dataproofs-dotnet/issues/33).

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
own terms it is minor material. The native-AOT work in this release is minor material on its own: a feature,
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
