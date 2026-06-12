# Research note: net-did proof-record model and verification-method/DID-document shapes

- **Source:** `/Users/moises/Projects/net-did` at commit `5ed8ff0a0da057c0db384074f8bc2a0830d0d4b8` (tree clean at time of audit, 2026-06-11).
- **Purpose (PRD §1.4 item 3):** net-did contributes two things to dataproofs-dotnet:
  1. The **`DataIntegrityProof` proof-record shape** (`type: "DataIntegrityProof"` + named `cryptosuite`) — the *model* reference for FR-1, reconciled into `DataProofsDotnet.Core`. Its `eddsa-jcs-2022` engine is an **identifier/encoding reference only**; the conformant signing mechanics (separate proof-config canonicalization + hash-concat) come from the zcap-dotnet port, NOT from net-did.
  2. The **verification-method / DID-document model shapes** — design input for `IVerificationMethodResolver` result types (FR-7). **No net-did type may appear in dataproofs**: the dependency rules (PRD §2.2) forbid referencing `net-did`; net-did later implements the resolver interface in an adapter at its own composition layer (precedent: didcomm-dotnet's `ISecretsResolver` + `DidComm.Adapters.NetDid`).

Everything below is verbatim-accurate to the commit; file paths are absolute.

---

## Part 1 — The `DataIntegrityProof` proof-record model and `eddsa-jcs-2022` engine

### 1.1 `DataIntegrityProof` record — full excerpt

File: `/Users/moises/Projects/net-did/src/NetDid.Core/Crypto/DataIntegrity/DataIntegrityProof.cs` (entire file):

```csharp
namespace NetDid.Core.Crypto.DataIntegrity;

/// <summary>
/// Represents a Data Integrity Proof per the W3C Data Integrity specification.
/// </summary>
public sealed record DataIntegrityProof
{
    public string Type { get; init; } = "DataIntegrityProof";

    /// <summary>The cryptosuite identifier (e.g., "eddsa-jcs-2022").</summary>
    public required string Cryptosuite { get; init; }

    /// <summary>The DID URL of the verification method used to create this proof (e.g., "did:key:z6Mkf...#z6Mkf...").</summary>
    public required string VerificationMethod { get; init; }

    /// <summary>Timestamp when this proof was created.</summary>
    public required DateTimeOffset Created { get; init; }

    /// <summary>The purpose of this proof (e.g., "assertionMethod", "authentication").</summary>
    public required string ProofPurpose { get; init; }

    /// <summary>The multibase-encoded signature value.</summary>
    public required string ProofValue { get; init; }
}
```

**Key observations for FR-1:**

- It is a `sealed record` with `init`-only properties; `Type` defaults to `"DataIntegrityProof"`, everything else is `required`.
- **There are NO `System.Text.Json` attributes on this type, and it is never serialized via STJ anywhere in net-did.** JSON member names are handled entirely by hand (see §1.2). dataproofs must define its own JSON treatment (zcap's `ZcapJsonOptions`/converters are the porting precedent per PRD FR-1).
- **Missing vs. the full VC Data Integrity 1.0 proof that FR-1 requires:** no `@context`, no `id`, no `expires`, no `challenge`, no `domain`, no `nonce`, no `previousProof`. net-did's record is the *shape* reference (modern `DataIntegrityProof` type + `cryptosuite` member, which zcap's 2020-era `Ed25519Signature2020` model predates), not a complete model — FR-1 extends it.
- **Required-ness differs from spec:** net-did makes `Created` and `ProofValue` `required`. In VC DI 1.0, `created` is OPTIONAL on a proof and `proofValue` is absent in a *proof configuration* (the pre-signing options object). dataproofs' model must allow `created` to be null and `proofValue` to be unset pre-signing.
- `Created` is `DateTimeOffset` (not string) in the core record — a reasonable choice, but see the wire-format note below about fractional seconds.

### 1.2 Wire serialization (the only place the proof hits JSON)

The core record never crosses the wire directly. did:webvh defines a parallel serializable class:

File: `/Users/moises/Projects/net-did/src/NetDid.Method.WebVh/Model/DataIntegrityProofValue.cs` — `public sealed class DataIntegrityProofValue` with `required string` properties `Type, Cryptosuite, VerificationMethod, Created, ProofPurpose, ProofValue` (note `Created` is a **string** here).

JSON member names are written manually in `/Users/moises/Projects/net-did/src/NetDid.Method.WebVh/LogEntrySerializer.cs` (`WriteProofArray`, ~line 160):

```csharp
writer.WriteString("type", proof.Type);
writer.WriteString("cryptosuite", proof.Cryptosuite);
writer.WriteString("verificationMethod", proof.VerificationMethod);
writer.WriteString("created", proof.Created);
writer.WriteString("proofPurpose", proof.ProofPurpose);
writer.WriteString("proofValue", proof.ProofValue);
```

So the wire names are exactly the spec's camelCase names: `type`, `cryptosuite`, `verificationMethod`, `created`, `proofPurpose`, `proofValue`.

`Created` formatting when converting core record → wire (e.g. `/Users/moises/Projects/net-did/src/NetDid.Method.WebVh/DidWebVhMethod.cs` ~lines 111, 364, 456):

```csharp
Created = proof.Created.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
```

i.e. **UTC, second precision, literal `Z`, no fractional seconds** — a valid XML-Schema `dateTimeStamp`. If dataproofs serializes `DateTimeOffset` with STJ defaults it would emit offsets/fractional seconds; pick an explicit converter (spec requires `dateTimeStamp`; second-precision `...Z` is the safe interop form and what both net-did and the W3C test vectors use).

Parsing back is `DateTimeOffset.Parse(proofValue.Created)` (LogChainValidator/WitnessValidator).

### 1.3 The `eddsa-jcs-2022` engine — structure, identifiers, encoding

File: `/Users/moises/Projects/net-did/src/NetDid.Core/Crypto/DataIntegrity/DataIntegrityProofEngine.cs`. Class: `public sealed class DataIntegrityProofEngine`, ctor `DataIntegrityProofEngine(ICryptoProvider crypto)`.

Full algorithm as implemented (header comment, verbatim):

```
/// Algorithm:
/// 1. Take the document (JSON string) WITHOUT the proof field
/// 2. JCS-canonicalize it (RFC 8785)
/// 3. Sign the canonical UTF-8 bytes with Ed25519
/// 4. Encode signature as multibase (base58btc)
```

Signing path (verbatim core of `CreateProofAsync`):

```csharp
public async Task<DataIntegrityProof> CreateProofAsync(
    string jsonWithoutProof,
    ISigner signer,
    string proofPurpose,
    DateTimeOffset created,
    CancellationToken ct = default)
{
    if (signer.KeyType != KeyType.Ed25519)
        throw new ArgumentException("eddsa-jcs-2022 requires an Ed25519 signer.", nameof(signer));

    // JCS-canonicalize and sign
    var canonicalBytes = JsonCanonicalization.CanonicalizeToUtf8(jsonWithoutProof);
    var signature = await signer.SignAsync(canonicalBytes, ct);

    // Multibase-encode the signature (base58btc)
    var proofValue = Multibase.Encode(signature, MultibaseEncoding.Base58Btc);

    // Build the verification method DID URL from the signer's public key
    var multibaseKey = signer.MultibasePublicKey;
    var verificationMethod = $"did:key:{multibaseKey}#{multibaseKey}";

    return new DataIntegrityProof
    {
        Cryptosuite = "eddsa-jcs-2022",
        VerificationMethod = verificationMethod,
        Created = created,
        ProofPurpose = proofPurpose,
        ProofValue = proofValue
    };
}
```

Verification path (`public bool VerifyProof(string jsonWithoutProof, DataIntegrityProof proof)`):
1. `if (proof.Cryptosuite != "eddsa-jcs-2022") return false;`
2. `ExtractPublicKeyFromDidKey(proof.VerificationMethod)` — **hard-codes did:key**; null → false.
3. `Multibase.Decode(proof.ProofValue)` inside try/catch; failure → false.
4. `JsonCanonicalization.CanonicalizeToUtf8(jsonWithoutProof)` then `_crypto.Verify(KeyType.Ed25519, publicKey, canonicalBytes, signature)` (synchronous, raw 32-byte Ed25519 public key, 64-byte raw signature).

**What dataproofs takes from here (identifiers/encoding):**
- Suite identifier string: `"eddsa-jcs-2022"`; proof type string: `"DataIntegrityProof"`.
- `proofValue` = multibase **base58-btc** of the raw signature → `z`-prefixed string (asserted in tests: `proof.ProofValue.Should().StartWith("z")`). In dataproofs, this encoding routes through **NetCid** (`Multibase.Encode(bytes, MultibaseEncoding.Base58Btc)` is exactly the NetCid 1.5.0 API net-did calls; no local multibase ships, PRD §1.4).
- Proof purposes are plain strings (`"assertionMethod"`, `"authentication"`).

**What dataproofs must NOT take (mechanics):**
- The engine **skips proof-configuration hashing entirely.** It signs `SHA-less` JCS bytes of the document alone — there is no proof-options canonicalization, no `SHA-256(canonicalProofConfig) ‖ SHA-256(canonicalDocument)` hash-concat, and **no proof field (`created`, `verificationMethod`, `proofPurpose`, `cryptosuite`, `@context`) is covered by the signature at all.** A conformant `eddsa-jcs-2022` verifier will reject net-did proofs and vice versa. The conformant mechanic is ported from zcap-dotnet's RDFC path (`ProofSigningPayloadBuilder`) and extended to JCS per PRD FR-5.
- Also non-conformant/limited: it never hashes at all (raw Ed25519 over canonical bytes — conformant eddsa-jcs-2022 signs the SHA-256-based hashData), it hard-codes did:key resolution inside the engine, it is single-suite, and verification is bool-only with swallowed exceptions (FR-2/FR-3 require structured results).

### 1.4 did:key extraction helpers (reference for VM-id handling, stays out of dataproofs Core)

Two public statics on the engine (full bodies in the source file, lines 101–165):

```csharp
public static string? ExtractDidKeyMultibase(string verificationMethod)
public static byte[]? ExtractPublicKeyFromDidKey(string verificationMethod)
```

Semantics worth keeping in mind when designing resolver contracts (these were security-hardened in net-did):
- Accepts `did:key:z6Mk...#z6Mk...` and `did:key:z6Mk...`; **if a fragment is present it MUST byte-equal the method-specific id** (ordinal compare) or the result is null — prevents `did:key:<attacker>#<authorized>` spoofing (see the comment in `LogChainValidator.ValidateProof`, ~line 178: authorized-key matching is exact equality, never substring).
- Rejects any input containing `?` or `/` (path/query/params) outright.
- `ExtractPublicKeyFromDidKey`: `Multibase.Decode(multibaseKey)` → `Multicodec.Decode(decoded)` returning `(ulong codec, byte[] rawKey)`; requires `codec == Multicodec.Ed25519Pub`; returns raw 32-byte key; any exception → null.

**dataproofs must not hard-code did:key** (PRD §1.2/§8) — this logic lives behind the `IVerificationMethodResolver` implemented downstream by net-did.

### 1.5 JCS canonicalizer (context only — zcap's is the porting source)

File: `/Users/moises/Projects/net-did/src/NetDid.Core/Crypto/Jcs/JsonCanonicalization.cs`, `public static class JsonCanonicalization` in `NetDid.Core.Crypto.Jcs`:

- `static string Canonicalize(string json)` / `static string Canonicalize(JsonElement element)` / `static byte[] CanonicalizeToUtf8(string json)`.
- RFC 8785: object members sorted with `StringComparer.Ordinal`; arrays preserved; strings escaped with the two-char escapes (`\" \\ \b \f \n \r \t`) and `\u00xx` for other control chars (< 0x20); `NaN`/`Infinity` throw `JsonException`.
- **Number handling caveat:** every number goes through `element.GetDouble()` then `FormatEs6Number(double)` — integers above 2^53 silently lose precision, and the `(decimal)value.ToString("0")` / `"R"`-format path is an approximation of ES6 `Number.prototype.toString()`. Do not port; zcap-dotnet's JCS canonicalizer is the designated source (PRD §1.4 item 1), and AC-1 W3C vectors are the conformance gate.

### 1.6 Crypto interfaces the engine rides on (signature-shape reference)

These are net-did types (cannot be referenced); dataproofs' equivalents come from **NetCrypto** (`ISigner`, `ICryptoProvider`, `IKeyStore`), which evolved from these same shapes.

`/Users/moises/Projects/net-did/src/NetDid.Core/ISigner.cs` (namespace `NetDid.Core`):

```csharp
public interface ISigner
{
    KeyType KeyType { get; }
    ReadOnlyMemory<byte> PublicKey { get; }                    // always available, even HSM-backed
    string MultibasePublicKey { get; }                          // multicodec-prefixed, multibase-encoded ("z6Mkf...")
    Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default);
}
```

`KeyStoreSigner` (`/Users/moises/Projects/net-did/src/NetDid.Core/Crypto/KeyStoreSigner.cs`) shows the non-exporting pattern dataproofs' AC-8 requires, and the canonical Multikey construction:

```csharp
public string MultibasePublicKey =>
    Multibase.Encode(Multicodec.Prefix(KeyType.GetMulticodec(), PublicKey.Span), MultibaseEncoding.Base58Btc);
```

`ICryptoProvider` (`/Users/moises/Projects/net-did/src/NetDid.Core/ICryptoProvider.cs`) — relevant detail confirmed: default `Sign`/`Verify` use **DER** for NIST-curve ECDSA; the `EcdsaSignatureFormat format` overloads give **IEEE P1363**; secp256k1 is natively 64-byte compact R‖S; Ed25519 ignores format. (Matches the PRD FR-13 gotcha; W3C DI ECDSA suites need P1363.)

`KeyType` enum (`/Users/moises/Projects/net-did/src/NetDid.Core/Crypto/KeyType.cs`): `Ed25519, X25519, P256, P384, Secp256k1, Bls12381G1, Bls12381G2, P521`.

NetCid 1.5.0 API surface used by net-did (the same calls dataproofs will make): `Multibase.Encode(byte[], MultibaseEncoding.Base58Btc)`, `Multibase.Decode(string)` (also decodes base64url via `"u" + ...`), `Multicodec.Decode(byte[]) → (ulong codec, byte[] raw)`, `Multicodec.Prefix(ulong code, ReadOnlySpan<byte>)`, constants `Multicodec.Ed25519Pub/X25519Pub/P256Pub/P384Pub/P521Pub/Secp256k1Pub/Bls12381G1Pub/Bls12381G2Pub` (all `ulong`).

`KeyTypeExtensions` (`/Users/moises/Projects/net-did/src/NetDid.Core/Crypto/KeyTypeExtensions.cs`) — multicodec mapping plus **raw key-byte conventions** (important for resolver result design):

```csharp
KeyType.Ed25519 => length == 32,
KeyType.X25519 => length == 32,
KeyType.P256 => length == 33,       // compressed SEC1 point
KeyType.P384 => length == 49,       // compressed SEC1 point
KeyType.P521 => length == 67,       // compressed SEC1 point
KeyType.Secp256k1 => length == 33,  // compressed SEC1 point
KeyType.Bls12381G1 => length == 48,
KeyType.Bls12381G2 => length == 96,
```

Also has `NormalizeToCompressed` (uncompressed `0x04` SEC1 → compressed) and `IsValidEcPoint` (on-curve validation; net-did validates EC points before use — `JwkConverter.ExtractPublicKey` runs `EcPointValidator.EnsureOnCurve` as RFC 7518 §6.2.2 invalid-curve defense).

### 1.7 Engine test behaviors (test-design reference)

`/Users/moises/Projects/net-did/tests/NetDid.Core.Tests/Crypto/DataIntegrity/DataIntegrityProofEngineTests.cs` asserts: round-trip create/verify; `Type == "DataIntegrityProof"`; `Cryptosuite == "eddsa-jcs-2022"`; `ProofValue` starts with `"z"`; tampered document fails; wrong key (VM swapped) fails; unknown cryptosuite fails; non-Ed25519 signer throws `ArgumentException` with `*Ed25519*`; **JCS property-order-insensitivity** (`{"b":"2","a":"1"}` verifies against proof created over `{"a":"1","b":"2"}`); did:key extraction with/without fragment, null for non-did:key. Good behavioral seeds for dataproofs suite tests, but conformance pins to W3C AC-1 vectors.

---

## Part 2 — Verification-method / DID-document model shapes (design input for `IVerificationMethodResolver`)

All types below are net-did's; **none may leak into dataproofs**. They are the best-tested .NET shapes for what a resolver result needs to express.

### 2.1 `VerificationMethod`

`/Users/moises/Projects/net-did/src/NetDid.Core/Model/VerificationMethod.cs` (entire class):

```csharp
using Microsoft.IdentityModel.Tokens;

namespace NetDid.Core.Model;

public sealed class VerificationMethod
{
    /// <summary>DID URL (validated at deserialization).</summary>
    public required string Id { get; init; }

    /// <summary>"Multikey", "JsonWebKey2020", "EcdsaSecp256k1VerificationKey2019"</summary>
    public required string Type { get; init; }

    /// <summary>The DID of the controller. Required for resolved documents. May be omitted in input documents...</summary>
    public Did Controller { get; init; }

    /// <summary>For Multikey representation.</summary>
    public string? PublicKeyMultibase { get; init; }

    /// <summary>For JWK representation.</summary>
    public JsonWebKey? PublicKeyJwk { get; init; }

    /// <summary>For did:ethr (CAIP-10 format).</summary>
    public string? BlockchainAccountId { get; init; }
}
```

Notes:
- `PublicKeyJwk` is `Microsoft.IdentityModel.Tokens.JsonWebKey` — the same JWK exception dataproofs `Core` carries (PRD §2.2 allows only `JsonWebKey` from that package in public API; AC-7).
- Wire names (manual converter in `DidDocumentSerializer.VerificationMethodJsonConverter`): `id`, `type`, `controller` (string), `publicKeyMultibase`, `publicKeyJwk`, `blockchainAccountId`; nulls omitted. **On write, the JWK emits only public members `kty/crv/x/y` — never `d/p/q/...`** (explicit private-material guard).
- `VerificationMethodRepresentation` enum: `Multikey` (→ `publicKeyMultibase`) | `JsonWebKey2020` (→ `publicKeyJwk`).
- `Did` is a validated readonly record struct (`/Users/moises/Projects/net-did/src/NetDid.Core/Model/Did.cs`): `Value/Method/MethodSpecificId`, throws on invalid syntax, implicit `string` conversions both ways; `default(Did)` has `Value == null` (used as "unset").

### 2.2 Verification relationships

Enum + wire names — `/Users/moises/Projects/net-did/src/NetDid.Core/Model/VerificationRelationship.cs`:

```csharp
public enum VerificationRelationship
{
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation
}
```

with `static class VerificationRelationshipNames` providing `const string` wire names (`"authentication"`, `"assertionMethod"`, `"keyAgreement"`, `"capabilityInvocation"`, `"capabilityDelegation"`), `ToWireName(this VerificationRelationship)` and `bool TryParse(string? wireName, out VerificationRelationship)` (**case-sensitive per spec**, unknown → false).

These five map 1:1 to VC DI 1.0 `proofPurpose` values — a dataproofs `ProofPurpose` model can mirror this enum+wire-name pattern (plus DI 1.0 treats purposes as open strings, so keep a string escape hatch).

Entry union type — `/Users/moises/Projects/net-did/src/NetDid.Core/Model/VerificationRelationshipEntry.cs`: a relationship entry is **either a reference (DID URL string) or an embedded `VerificationMethod` — never both, never neither**:

```csharp
public sealed class VerificationRelationshipEntry
{
    public string? Reference { get; }                 // set when IsReference == true
    public VerificationMethod? EmbeddedMethod { get; } // set when IsReference == false
    public bool IsReference => Reference is not null;
    // private ctor; factories:
    public static VerificationRelationshipEntry FromReference(string didUrl);
    public static VerificationRelationshipEntry FromEmbedded(VerificationMethod method);
    public static implicit operator VerificationRelationshipEntry(string didUrl); // => FromReference
}
```

JSON converter (`VerificationRelationshipEntryJsonConverter`): string token → reference; object token → embedded VM; anything else throws. On write: reference → bare string, embedded → VM object. This is the exact JSON-LD wire shape of DID Core §5.3.

### 2.3 `DidDocument`

`/Users/moises/Projects/net-did/src/NetDid.Core/Model/DidDocument.cs` — `public sealed record DidDocument` with:

```csharp
public Did Id { get; init; }                                              // default == unset (input docs)
public IReadOnlyList<string>? AlsoKnownAs { get; init; }
public IReadOnlyList<Did>? Controller { get; init; }                      // string when 1, array when >1 on wire
public IReadOnlyList<VerificationMethod>? VerificationMethod { get; init; }
public IReadOnlyList<VerificationRelationshipEntry>? Authentication { get; init; }
public IReadOnlyList<VerificationRelationshipEntry>? AssertionMethod { get; init; }
public IReadOnlyList<VerificationRelationshipEntry>? KeyAgreement { get; init; }
public IReadOnlyList<VerificationRelationshipEntry>? CapabilityInvocation { get; init; }
public IReadOnlyList<VerificationRelationshipEntry>? CapabilityDelegation { get; init; }
public IReadOnlyList<Service>? Service { get; init; }
public IReadOnlyList<object>? Context { get; init; }                      // "@context"; strings or JsonElement
public IReadOnlyDictionary<string, JsonElement>? AdditionalProperties { get; init; }
```

Relationship lookup is by extension method (keeps the record a pure data shape) — `/Users/moises/Projects/net-did/src/NetDid.Core/Model/DidDocumentExtensions.cs`:

```csharp
public static IReadOnlyList<VerificationRelationshipEntry>? GetRelationshipEntries(
    this DidDocument document, VerificationRelationship relationship)   // switch over the five lists
// + string overload via VerificationRelationshipNames.TryParse (unknown name → null)
```

Serialization: `/Users/moises/Projects/net-did/src/NetDid.Core/Serialization/DidDocumentSerializer.cs` — all manual `Utf8JsonWriter` converters (camelCase, nulls omitted); relationship arrays written under the five wire names; `@context` computed from VM types (`Multikey` → `https://w3id.org/security/multikey/v1`, `JsonWebKey2020` → `https://w3id.org/security/suites/jws-2020/v1`).

### 2.4 net-did's own `IVerificationMethodResolver` — the strongest design precedent

net-did **already defines** the exact interface dataproofs FR-7 needs, built for zcap-dotnet's identical requirement. File: `/Users/moises/Projects/net-did/src/NetDid.Core/Resolution/IVerificationMethodResolver.cs` (entire file):

```csharp
using NetDid.Core.Crypto;

namespace NetDid.Core.Resolution;

/// <summary>
/// Resolves a DID URL to a verification method's key type and public key bytes.
/// Used by zcap-dotnet for ZCAP verification.
/// </summary>
public interface IVerificationMethodResolver
{
    /// <summary>
    /// Resolve a DID URL to the key type and raw public key bytes of the verification method it identifies.
    /// Returns null if the DID URL cannot be resolved or the verification method has no extractable key.
    /// </summary>
    Task<(KeyType KeyType, byte[] PublicKey)?> ResolveKeyAsync(
        string didUrl,
        CancellationToken ct = default);
}
```

Default implementation — `/Users/moises/Projects/net-did/src/NetDid.Core/Resolution/DefaultVerificationMethodResolver.cs` (key body):

```csharp
var result = await _dereferencer.DereferenceAsync(didUrl, ct: ct);
if (result.ContentStream is not VerificationMethod vm)
    return null;

// Try PublicKeyMultibase first (Multikey path)
if (vm.PublicKeyMultibase is not null)
{
    var decoded = Multibase.Decode(vm.PublicKeyMultibase);
    var (codec, rawKey) = Multicodec.Decode(decoded);
    var keyType = KeyTypeExtensions.ToKeyType(codec);
    return (keyType, rawKey);
}

// Try PublicKeyJwk (JWK path)
if (vm.PublicKeyJwk is not null)
{
    var (keyType, publicKey) = JwkConverter.ExtractPublicKey(vm.PublicKeyJwk);
    return (keyType, publicKey);
}

// BlockchainAccountId only — no extractable key
return null;
```

Behavioral facts a dataproofs adapter will inherit:
- Multikey wins over JWK when both are present.
- EC public keys come back as **compressed SEC1** (33/49/67 bytes; JWK path reconstructs `0x02|0x03 ‖ x` after on-curve validation); Ed25519/X25519 as raw 32 bytes. dataproofs' suite verify path (NetCrypto) must accept these formats.
- Null is the only failure signal — no error-cause channel (contrast with the relationship resolver below, which is tri-state).

### 2.5 Proof-purpose authorization — the separate relationship resolver

VC DI verification must check that the VM is authorized for the proof's `proofPurpose` against the **controller's** document. net-did models this as a second interface, deliberately separate from key resolution. File: `/Users/moises/Projects/net-did/src/NetDid.Core/Resolution/IVerificationRelationshipResolver.cs`:

```csharp
public interface IVerificationRelationshipResolver
{
    Task<VerificationRelationshipAuthorizationResult> IsAuthorizedForRelationshipAsync(
        string controllerDid,
        string verificationMethodDidUrl,
        VerificationRelationship relationship,
        CancellationToken ct = default);
}
```

Result type (`VerificationRelationshipAuthorizationResult.cs`) — `sealed record` with `required AuthorizationDecision Decision`, `string? ResolutionError` (e.g. `"notFound"`, `"invalidDid"`, `"methodNotSupported"`), `string? Message` ("never logs key material"), and factories `Authorized()` / `NotAuthorized()` / `NotResolvable(error, message)`.

```csharp
public enum AuthorizationDecision { Authorized, NotAuthorized, ControllerNotResolvable }
```

The doc comment explains the tri-state rationale: *"keeps 'infrastructure failed' distinct from 'controller's document said no', so a verifier can fail closed and log the underlying cause instead of silently treating both as denial."* — directly applicable to dataproofs' structured verification results (FR-3).

Default impl (`DefaultVerificationRelationshipResolver.cs`) matching/normalization rules worth replicating:
- Resolves the **controller** DID (not the DID embedded in the VM URL) — honors cross-DID references and per-purpose key separation.
- Matches both referenced and embedded entries; entry id = `Reference` or `EmbeddedMethod.Id`.
- Normalization (`NormalizeVmId`): `"#k1"` → `"{controllerDid}#k1"`; bare `"k1"` (no `:`) → `"{controllerDid}#k1"`; absolute DID URLs unchanged. Comparison is **ordinal**, query/path NOT stripped.
- Does not walk the resolved document's own `controller` list — callers with multiple controllers query each.

Fragment dereferencing (`DefaultDidUrlDereferencer.FindByFragment`, `/Users/moises/Projects/net-did/src/NetDid.Core/Resolution/DefaultDidUrlDereferencer.cs` ~line 206) additionally supports an optional relationship **filter** (`DidUrlDereferencingOptions.VerificationRelationship`, a wire-name string): when set, only VMs present in that relationship (embedded, or referenced with matching fragment) are returned. This is the hook by which a single resolver call can enforce proof purpose — an alternative to the two-interface split.

`IDidUrlDereferencer` / `DidUrlDereferencingResult` (for completeness — the adapter layer's plumbing): `DereferenceAsync(string didUrl, DidUrlDereferencingOptions?, CancellationToken)` → record with `DereferencingMetadata`, `object? ContentStream` (a `VerificationMethod`, `Service`, `DidDocument`, or string), `ContentMetadata`.

### 2.6 Implications for dataproofs' `IVerificationMethodResolver` (FR-7)

What the net-did shapes argue the dataproofs-owned interface/result should carry — expressed only in dataproofs/NetCrypto/NetCid/BCL types:

1. **Input:** the proof's `verificationMethod` string (a DID URL, treated opaquely) + `CancellationToken`. Optionally the proof purpose (see 4).
2. **Result must include:** key type (NetCrypto `KeyType`) + public key bytes. Document the byte conventions (raw 32B Ed25519; compressed SEC1 for EC — matching what NetCid `Multicodec.Decode` of a Multikey yields). Consider exposing the Multikey string and/or `JsonWebKey` as the "as-found" representation (Core's JWK exception covers this), plus the VM `id` and `controller` strings — verification algorithms need the controller for purpose-authorization.
3. **Failure model:** prefer a structured result over net-did's bare nullable tuple — the tri-state `AuthorizationDecision` pattern (resolution-infrastructure failure ≠ not-found ≠ unauthorized) is the proven shape for fail-closed verification with diagnosable causes.
4. **Proof-purpose authorization:** either (a) a second method/interface mirroring `IsAuthorizedForRelationshipAsync(controller, vmUrl, purpose)`, or (b) an optional purpose parameter on resolve (mirroring `DidUrlDereferencingOptions.VerificationRelationship`). net-did can implement either from existing pieces. Purposes should be modeled as the five well-known names (constants like `VerificationRelationshipNames`) + open string, since DI 1.0 purposes are extensible.
5. **No enum leakage:** net-did `KeyType` and NetCrypto `KeyType` are distinct types (same member names for the common set: `Ed25519, X25519, P256, P384, Secp256k1, P521`, plus BLS in net-did). The adapter (owned by net-did) does the mapping; dataproofs only ever sees NetCrypto's.

---

## Risks / gotchas for the PRD's assumptions

1. **net-did's engine is non-conformant with `eddsa-jcs-2022`** (confirmed at this commit): no proof-config canonicalization/hash, no SHA-256 of the document, proof options entirely unsigned, did:key hard-coded. PRD §1.4 already says to take only identifiers/encoding from it — nothing in the source contradicts that, but any "port net-did's engine" shortcut would ship a non-interoperable suite. zcap's RDFC hash-concat mechanic + W3C AC-1 vectors are the authority.
2. **The core `DataIntegrityProof` record is materially narrower than FR-1** (no `@context`/`id`/`expires`/`challenge`/`domain`/`nonce`/`previousProof`; `created`/`proofValue` are `required` where the spec allows their absence). It is a shape seed, not a copy-paste; FR-1's field list governs.
3. **No JSON serialization metadata exists to copy** — net-did never STJ-serializes the proof record; wire names live in hand-written `Utf8JsonWriter` code in the webvh package. dataproofs must build converters fresh (zcap's `ZcapJsonOptions` precedent).
4. **`created` wire format:** net-did emits `yyyy-MM-ddTHH:mm:ssZ` (second precision, UTC). A default STJ `DateTimeOffset` converter would not match; dataproofs needs an explicit dateTimeStamp converter to round-trip vectors byte-identically under JCS.
5. **EC key-byte conventions:** resolver results deliver **compressed SEC1** EC points (and JWK paths reconstruct compressed form). If NetCrypto's verify path expects uncompressed/other encodings for P-256/P-384, the suites need a documented normalization step; otherwise W3C ECDSA vectors will fail at the adapter boundary.
6. **net-did's JCS canonicalizer has double-precision number handling** (`GetDouble()` + ES6 approximation) — silently corrupts integers > 2^53. It must not become the dataproofs canonicalizer by accident; the zcap canonicalizer is the designated port and should be vector-tested for the same trap.
7. **Resolver error semantics:** net-did's `IVerificationMethodResolver` returns `null` for *all* failures. If dataproofs copies that contract verbatim, verification cannot distinguish "resolution infrastructure down" from "no such key" (fail-closed-with-cause is lost). The tri-state `AuthorizationDecision` pattern in the same codebase is the better precedent.
8. **Proof-purpose checking is a separate concern in net-did** (`IVerificationRelationshipResolver`). If dataproofs' FR-7 interface only resolves keys, the DI "verification method controller authorizes the proof purpose" check needs its own seam — decide at design time whether FR-7 is one interface or two, or the purpose-filter-parameter style of `DidUrlDereferencingOptions.VerificationRelationship`.
9. **VM-id matching hygiene:** net-did learned (and documented in `LogChainValidator`) that authorized-key matching must be exact/ordinal — substring or prefix matching enables `did:key:<attacker>#<authorized>` spoofing. The same applies to any dataproofs logic that compares `proof.verificationMethod` against allow-lists or document entries; fragment/relative-id normalization should follow the `NormalizeVmId` rules (`#k1`/`k1` → `{controller}#k1`, ordinal compare, no query stripping).
