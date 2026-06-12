# Porting inventory: `zcap-dotnet` → DataProofsDotnet (embedded-proof / Data Integrity family)

**Source:** `/Users/moises/Projects/zcap-dotnet` @ commit `368ced0eea5c78f8820c94c5cdafb586ed2896da` (read-only audit, 2026-06-11).
**PRD context:** dataproofs-prd.md §1.4 item 1 — `ZcapLd.Core` is the porting source for `Core` + `Rdfc` (FR-1, FR-2, FR-5, FR-11).
**Caution for coders:** the source repo contains stale copies under `.claude/worktrees/*` — port ONLY from `src/ZcapLd.Core/` and `tests/ZcapLd.Core.Tests/` in the main tree.

**Package versions in play** (from `src/ZcapLd.Core/ZcapLd.Core.csproj` + `obj/project.assets.json`):

| Package | Version | Notes |
|---|---|---|
| `dotNetRdf.Core` | **3.5.1** | netstandard2.0; depends on **Newtonsoft.Json 13.0.4** (JSON-LD machinery is JToken-based), AngleSharp 1.4.0, HtmlAgilityPack 1.12.4, Microsoft.Extensions.Configuration 10.0.2 |
| `NetDid.Core` / `NetDid.Method.Key` | 1.3.1 | supplies `DefaultCryptoProvider` + `EcdsaSignatureFormat` — **replaced by NetCrypto on port** |
| `NetCid` | 1.5.0 (transitive via NetDid) | supplies `Multibase` used by `MultibaseCodec` |
| TFM | net10.0 | `InternalsVisibleTo: ZcapLd.Core.Tests`; embeds `Cryptography/Contexts/*.jsonld` as resources |

The csproj carries this comment (the P1363 rationale, verbatim):

```xml
<!-- NetDid 1.3.0 made DER the default for its legacy ECDSA Sign/Verify overloads. The W3C
     `ecdsa-2019` suite this library implements requires IEEE P1363 (fixed-width r||s), so
     CryptoSuite calls NetDid's format-aware overloads with EcdsaSignatureFormat.IeeeP1363.
     See CryptoSuite.cs. -->
```

---

## 1. Cryptosuite provider and suites

### 1.1 `ICryptoSuiteProvider` — `src/ZcapLd.Core/Cryptography/ICryptoSuiteProvider.cs`

```csharp
namespace ZcapLd.Core.Cryptography;

public interface ICryptoSuiteProvider
{
    ICryptoSuite? GetByProofType(string proofType);  // verification: select algorithm from proof.type
    ICryptoSuite? GetByKeyType(string keyType);      // signing: select suite from resolved key material
}
```

### 1.2 `CryptoSuiteProvider` — `src/ZcapLd.Core/Cryptography/CryptoSuiteProvider.cs`

Two `ConcurrentDictionary<string, ICryptoSuite>` maps (`StringComparer.Ordinal`), keyed by `suite.ProofType` and `suite.KeyType`. `Register(ICryptoSuite suite)` throws on null and **replaces** any existing entry for the same proof/key type ("last registered wins" — the RDFC tests exploit this to swap in an RDFC-flavored Ed25519 suite). `GetBy*` return `null` for null/empty input or a miss.

> Port note: dataproofs keys suites by the `cryptosuite` field value (`eddsa-jcs-2022`, etc.), not by `proof.type` (always `DataIntegrityProof`) — the registry mechanics transfer, the key changes.

### 1.3 `ICryptoSuite` — `src/ZcapLd.Core/Cryptography/ICryptoSuite.cs`

```csharp
public interface ICryptoSuite
{
    string ProofType { get; }   // e.g. "Ed25519Signature2020" — value written into proof.type
    string KeyType { get; }     // e.g. "Ed25519VerificationKey2020" — EXACT ordinal match against
                                // ResolvedKey.KeyType at verify time (Issue #68); synonyms
                                // (Multikey, JsonWebKey2020, ...VerificationKey2018) are rejected
    string ContextUrl { get; }  // e.g. "https://w3id.org/security/suites/ed25519-2020/v1"

    byte[] Sign(byte[] data, byte[] privateKey);                       // RAW private key — replace with NetCrypto ISigner (AC-8)
    bool Verify(byte[] data, byte[] signature, byte[] publicKey);

    string CanonicalizationMethod => "JCS";   // default interface member; suites opt in to "RDFC-1.0"
}
```

`CanonicalizationMethod` is a **default interface member** returning `"JCS"`; this is how a suite selects its canonicalizer (see `SigningService.ResolveCanonicalizer` / `VerificationService.ResolveCanonicalizer`, both of which throw `ZcapLd.Core.Exceptions.CryptographicException` when no canonicalizer is registered for the method).

### 1.4 `CryptoSuite` (the only concrete impl; Ed25519Signature2020 + EcdsaSecp256r1Signature2019) — `src/ZcapLd.Core/Cryptography/CryptoSuite.cs` (full file)

```csharp
using NetDid.Core.Crypto;

namespace ZcapLd.Core.Cryptography;

public class CryptoSuite : ICryptoSuite
{
    private static readonly DefaultCryptoProvider Crypto = new();
    private readonly NetDid.Core.Crypto.KeyType _netDidKeyType;

    public CryptoSuite(string proofType, string keyType, string contextUrl,
        NetDid.Core.Crypto.KeyType netDidKeyType)
    {
        ProofType = proofType ?? throw new ArgumentNullException(nameof(proofType));
        KeyType = keyType ?? throw new ArgumentNullException(nameof(keyType));
        ContextUrl = contextUrl ?? throw new ArgumentNullException(nameof(contextUrl));
        _netDidKeyType = netDidKeyType;
    }

    public string ProofType { get; }
    public string KeyType { get; }
    public string ContextUrl { get; }

    // W3C Data Integrity suites (ecdsa-2019 / EcdsaSecp256r1Signature2019) and JOSE put the raw
    // ECDSA signature on the wire as IEEE P1363 fixed-width r‖s — NOT ASN.1 DER. NetDid 1.3.0
    // defaults its legacy Sign/Verify overloads to DER, so we explicitly request P1363 via the
    // format-aware overloads. Non-ECDSA key types (Ed25519, secp256k1, BLS) ignore the format and
    // return their algorithm-native wire form, so passing P1363 unconditionally is safe.
    public byte[] Sign(byte[] data, byte[] privateKey)
        => Crypto.Sign(_netDidKeyType, privateKey, data, EcdsaSignatureFormat.IeeeP1363);

    public bool Verify(byte[] data, byte[] signature, byte[] publicKey)
        => Crypto.Verify(_netDidKeyType, publicKey, data, signature, EcdsaSignatureFormat.IeeeP1363);

    public static CryptoSuite Ed25519() => new(
        "Ed25519Signature2020",
        "Ed25519VerificationKey2020",
        "https://w3id.org/security/suites/ed25519-2020/v1",
        NetDid.Core.Crypto.KeyType.Ed25519);

    public static CryptoSuite P256() => new(
        "EcdsaSecp256r1Signature2019",
        "EcdsaSecp256r1VerificationKey2019",
        "https://w3id.org/security/suites/ecdsa-2019/v1",
        NetDid.Core.Crypto.KeyType.P256);
}
```

**`EcdsaSignatureFormat.IeeeP1363` usage sites (entire repo, src):** only `CryptoSuite.cs` lines 35 and 38 above. Test pinning it: `tests/ZcapLd.Core.Tests/Cryptography/CryptoSuiteTests.cs:115` `P256_Sign_ProducesIeeeP1363WireFormat_NotDer` (asserts 64-byte signature, not DER `0x30...`). **Retain P1363 in the NetCrypto reroute** — PRD FR-13 confirms NetCrypto's default `ICryptoProvider.Sign` returns DER for NIST curves, so the port MUST use NetCrypto's `EcdsaSignatureFormat.IeeeP1363` overload for P-256/P-384.

There is also a test/example-only RDFC suite wrapper, `tests/ZcapLd.Core.Tests/Helpers/RdfcEd25519CryptoSuite.cs` (duplicated at `examples/ZcapLd.Examples/RdfcEd25519CryptoSuite.cs`): wraps `CryptoSuite.Ed25519()` and overrides `CanonicalizationMethod => "RDFC-1.0"`. This is how the RDFC pipeline is currently activated — there is **no first-class RDFC suite in src/**.

---

## 2. Canonicalizer abstraction

### 2.1 `IDocumentCanonicalizer` — `src/ZcapLd.Core/Cryptography/IDocumentCanonicalizer.cs`

```csharp
public interface IDocumentCanonicalizer
{
    string Method { get; }                 // "JCS" or "RDFC-1.0"
    byte[] Canonicalize(object document);  // accepts C# object OR raw JSON string; returns canonical UTF-8 bytes
}
```

### 2.2 `IDocumentCanonicalizerProvider` / `DocumentCanonicalizerProvider` — `src/ZcapLd.Core/Cryptography/IDocumentCanonicalizerProvider.cs`, `DocumentCanonicalizerProvider.cs`

Same registry pattern as the suite provider: `ConcurrentDictionary<string, IDocumentCanonicalizer>` keyed by `Method` (ordinal), `Register` replaces duplicates, `GetByMethod` returns null for null/empty/miss.

### 2.3 JCS path: `JcsDocumentCanonicalizer` + static `JsonCanonicalizer`

`src/ZcapLd.Core/Cryptography/JcsDocumentCanonicalizer.cs` is a thin adapter (`Method => "JCS"`, delegates to `JsonCanonicalizer.Canonicalize`, throws on null).

`src/ZcapLd.Core/Cryptography/JsonCanonicalizer.cs` — the actual "simplified RFC 8785" implementation. Pipeline: `JsonSerializer.Serialize(document, CanonicalJsonOptions)` → `JsonDocument.Parse` → recursive `WriteElementSorted` into a `Utf8JsonWriter`. Key excerpts:

```csharp
private static readonly JsonWriterOptions CanonicalWriterOptions = new()
{
    Indented = false,
    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
};

private static readonly JsonSerializerOptions CanonicalJsonOptions = new()
{
    WriteIndented = false,
    PropertyNamingPolicy = null, // Preserve original names
    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
};
```

`UnsafeRelaxedJsonEscaping` is load-bearing: RFC 8785 §3.2.2.2 escapes only `"` `\` and control chars; STJ's default encoder escapes `+ < > & '` to `\uXXXX`, which silently diverges canonical bytes from conformant peers (zcap Issue #36 — e.g. timestamps containing `+00:00`).

The sorted-object writer:

```csharp
case JsonValueKind.Object:
    writer.WriteStartObject();
    foreach (var property in element.EnumerateObject().OrderBy(p => p.Name))
    {
        // Skip null-valued properties so that JsonElement objects
        // (from JSON round-trips) produce the same canonical form
        // as native C# objects serialized with WhenWritingNull.
        if (property.Value.ValueKind == JsonValueKind.Null)
            continue;
        writer.WritePropertyName(property.Name);
        WriteElementSorted(writer, property.Value);
    }
    writer.WriteEndObject();
    break;
...
case JsonValueKind.Number:
    if (element.TryGetInt32(out var intValue))       writer.WriteNumberValue(intValue);
    else if (element.TryGetInt64(out var longValue)) writer.WriteNumberValue(longValue);
    else if (element.TryGetDouble(out var doubleValue)) writer.WriteNumberValue(doubleValue);
    break;
```

Also exposes `CanonicalizeString(string json)`, `RemoveProofField(string json)` (drops **every** `"proof"` property at any object level it recurses through — note the test `RemoveProofField_WithNestedObjects_ShouldOnlyRemoveTopLevelProof` pins the actual observed behavior), and `CanonicalizeWithoutProof(object)`. Only `Canonicalize` is used by the live signing path (via `JcsDocumentCanonicalizer`); `RemoveProofField`/`CanonicalizeWithoutProof` are legacy helpers.

**RFC 8785 conformance gaps — do NOT port blindly (PRD already routes JCS through NetCid for FR-5):**
1. **Key ordering:** `OrderBy(p => p.Name)` uses `Comparer<string>.Default` = culture-sensitive `string.CompareTo`, NOT RFC 8785's UTF-16 code-unit ordering. Agrees for zcap's all-lowercase ASCII keys; diverges for mixed-case (`"Type"` vs `"created"`) or non-ASCII keys.
2. **Numbers:** `WriteNumberValue(double)` is .NET shortest-round-trip formatting, not ECMAScript `Number::toString` serialization (RFC 8785 §3.2.2.3) — diverges for large/small magnitudes (`1e21`, exponent formatting).
3. **Null-dropping:** explicit JSON `null` members are *removed* during canonicalization. Pure JCS preserves them. Deliberate in zcap (model/wire equivalence); wrong for arbitrary documents.

### 2.4 RDFC path: `RdfcDocumentCanonicalizer` — `src/ZcapLd.Core/Cryptography/RdfcDocumentCanonicalizer.cs` (full file)

```csharp
using System.Text;
using System.Text.Json;
using VDS.RDF;
using VDS.RDF.JsonLd;
using VDS.RDF.Parsing;

namespace ZcapLd.Core.Cryptography;

public class RdfcDocumentCanonicalizer : IDocumentCanonicalizer
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = null,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static readonly JsonLdProcessorOptions ParserOptions = new()
    {
        DocumentLoader = CachedContextLoader.LoadDocument
    };

    public string Method => "RDFC-1.0";

    public byte[] Canonicalize(object document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var jsonString = document is string s
            ? s
            : JsonSerializer.Serialize(document, SerializerOptions);

        var store = new TripleStore();
        var parser = new JsonLdParser(ParserOptions);
        parser.Load(store, new StringReader(jsonString));

        var canonicalizer = new RdfCanonicalizer();
        var result = canonicalizer.Canonicalize(store);

        return Encoding.UTF8.GetBytes(result.SerializedNQuads);
    }
}
```

**Exact dotNetRDF APIs used (verified against dotNetRdf.Core 3.5.1 XML docs):**
- `VDS.RDF.TripleStore` (in-memory dataset).
- `VDS.RDF.Parsing.JsonLdParser(JsonLdProcessorOptions)` + `.Load(ITripleStore, TextReader)` — JSON-LD 1.1 expansion → RDF. Internally **Newtonsoft.Json (JToken)** based.
- `VDS.RDF.JsonLd.JsonLdProcessorOptions` — only `DocumentLoader` is set (type: `Func<Uri, JsonLdLoaderOptions, RemoteDocument>`); all other options (processing mode, safe mode, etc.) are dotNetRDF defaults. No "fail on dropped/unknown term" behavior is configured.
- `VDS.RDF.RdfCanonicalizer` — RDFC-1.0. Single constructor `RdfCanonicalizer(string hashAlgorithm = "SHA256")` (zcap calls the parameterless form ⇒ SHA-256 internal hashing). `Canonicalize(ITripleStore)` returns nested type `RdfCanonicalizer.CanonicalizedRdfDataset` with property `SerializedNQuads` (string; sorted canonical N-Quads, `_:c14nN` labels) and fields `InputDataset`, `OutputDataset`, `IssuedIdentifiersMap`.
- `VDS.RDF.JsonLd.RemoteDocument` — `{ Document (JToken or string), DocumentUrl, ContextUrl }`.
- `VDS.RDF.JsonLd.DefaultDocumentLoader.LoadJson(Uri, JsonLdLoaderOptions)` — synchronous HTTP fetch fallback.

**Quirks:**
- The JSON-LD layer is **Newtonsoft-coupled**: `RemoteDocument.Document` takes a `JToken` (`Newtonsoft.Json.Linq.JToken.Parse(...)` in `CachedContextLoader`). The STJ↔string↔JToken round-trip at the canonicalizer boundary is the seam: documents enter as STJ-serialized strings and dotNetRDF re-parses them.
- For `ecdsa-rdfc-2019` with **P-384**, the vc-di-ecdsa spec requires SHA-384 both for the hash-concat AND inside RDFC-1.0 — pass `"SHA384"` to the `RdfCanonicalizer(string)` ctor for that curve. zcap never does this (Ed25519/P-256 only, SHA-256 everywhere).
- Tests confirm `Canonicalize` accepts a raw JSON string and produces identical bytes regardless of source property order (RDFC sorts quads).

---

## 3. `ProofSigningPayloadBuilder` — FULL VERBATIM — `src/ZcapLd.Core/Cryptography/ProofSigningPayloadBuilder.cs`

This is the heart of the port (PRD FR-2/FR-5/FR-11). It is `internal static` (visible to tests via `InternalsVisibleTo`).

```csharp
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Builds deterministic signing payloads for capabilities and invocations.
///
/// W3C Verifiable Credentials Data Integrity convention: the verification payload
/// is the document's own top-level fields plus a "proof" field containing every
/// proof field except "proofValue". Cross-stack interop (zcap-py, JS, Rust)
/// relies on this exact shape — any wrapper or hand-picked proof-field whitelist
/// breaks signature compatibility silently.
///
/// Two canonicalization strategies are supported:
/// - JCS: serialize the flat verification payload through JSON-then-canonicalize
///   (RFC 8785 — alphabetically sorted keys, no whitespace).
/// - RDFC-1.0: canonicalize document and proof options separately, SHA-256 each,
///   concatenate (per W3C Data Integrity spec).
/// </summary>
internal static class ProofSigningPayloadBuilder
{
    private static readonly JcsDocumentCanonicalizer DefaultJcs = new();

    /// <summary>
    /// Sign-time and verifier-time JSON options live in <see cref="ZcapJsonOptions.Default"/>
    /// so the <see cref="CaveatJsonConverter"/> registration is shared. Without this,
    /// sign-time and wire-emit serializers diverge for any non-trivial caveat (Issue #39).
    /// </summary>
    private static JsonSerializerOptions ModelSerializerOptions => ZcapJsonOptions.Default;

    public static Capability CloneCapabilityWithoutProof(Capability capability)
    {
        ArgumentNullException.ThrowIfNull(capability);

        return new Capability
        {
            Context = capability.Context,
            Id = capability.Id,
            ParentCapability = capability.ParentCapability,
            Controller = capability.Controller,
            InvocationTarget = capability.InvocationTarget,
            Expires = capability.Expires,
            AllowedAction = capability.AllowedAction,
            Caveat = capability.Caveat,
            // Preserve unmodeled wire fields so JCS canonicalization sees them.
            AdditionalProperties = capability.AdditionalProperties,
            Proof = null
        };
    }

    public static Invocation CloneInvocationWithoutProof(Invocation invocation)
    {
        ArgumentNullException.ThrowIfNull(invocation);

        return new Invocation
        {
            Id = invocation.Id,
            Capability = invocation.Capability,
            CapabilityAction = invocation.CapabilityAction,
            InvocationTarget = invocation.InvocationTarget,
            Proof = null
        };
    }

    public static byte[] CanonicalizeCapabilityPayload(
        Capability capabilityWithoutProof,
        Proof proof,
        IDocumentCanonicalizer? canonicalizer = null)
    {
        ArgumentNullException.ThrowIfNull(capabilityWithoutProof);
        ArgumentNullException.ThrowIfNull(proof);

        canonicalizer ??= DefaultJcs;

        if (canonicalizer.Method == "RDFC-1.0")
        {
            return CanonicalizeCapabilityRdfc(capabilityWithoutProof, proof, canonicalizer);
        }

        return CanonicalizeCapabilityJcs(capabilityWithoutProof, proof, canonicalizer);
    }

    public static byte[] CanonicalizeInvocationPayload(
        Invocation invocationWithoutProof,
        Proof proof,
        IDocumentCanonicalizer? canonicalizer = null)
    {
        ArgumentNullException.ThrowIfNull(invocationWithoutProof);
        ArgumentNullException.ThrowIfNull(proof);

        canonicalizer ??= DefaultJcs;

        if (canonicalizer.Method == "RDFC-1.0")
        {
            return CanonicalizeInvocationRdfc(invocationWithoutProof, proof, canonicalizer);
        }

        return CanonicalizeInvocationJcs(invocationWithoutProof, proof, canonicalizer);
    }

    // ─── JCS — W3C Data Integrity flat shape ───────────────────────────

    private static byte[] CanonicalizeCapabilityJcs(
        Capability capabilityWithoutProof, Proof proof, IDocumentCanonicalizer canonicalizer)
    {
        var doc = ToFieldDictionary(capabilityWithoutProof);
        doc["proof"] = ToFieldDictionary(proof, exclude: "proofValue");
        return canonicalizer.Canonicalize(doc);
    }

    private static byte[] CanonicalizeInvocationJcs(
        Invocation invocationWithoutProof, Proof proof, IDocumentCanonicalizer canonicalizer)
    {
        var doc = ToFieldDictionary(invocationWithoutProof);
        doc["proof"] = ToFieldDictionary(proof, exclude: "proofValue");
        return canonicalizer.Canonicalize(doc);
    }

    // ─── RDFC-1.0 — W3C Data Integrity hash-concat shape ───────────────
    // Per spec: canonicalize document and proof options separately,
    // SHA-256 hash each, concatenate hashes → signing input.

    private static byte[] CanonicalizeCapabilityRdfc(
        Capability capabilityWithoutProof, Proof proof, IDocumentCanonicalizer canonicalizer)
    {
        // Proof options carry every proof field except proofValue, plus the document's @context
        // so JSON-LD processing has the same vocabulary the document uses.
        var proofOptions = ToFieldDictionary(proof, exclude: "proofValue");
        proofOptions["@context"] = JsonSerializer.SerializeToElement(
            capabilityWithoutProof.Context, ModelSerializerOptions);

        return ConcatenateHashes(
            canonicalizer.Canonicalize(capabilityWithoutProof),
            canonicalizer.Canonicalize(proofOptions));
    }

    private static byte[] CanonicalizeInvocationRdfc(
        Invocation invocationWithoutProof, Proof proof, IDocumentCanonicalizer canonicalizer)
    {
        // Invocations don't carry @context on the model, so add the ZCAP-LD default for JSON-LD processing.
        const string ZcapContext = "https://w3id.org/zcap/v1";

        var invocationDoc = ToFieldDictionary(invocationWithoutProof);
        invocationDoc["@context"] = JsonSerializer.SerializeToElement(ZcapContext, ModelSerializerOptions);

        var proofOptions = ToFieldDictionary(proof, exclude: "proofValue");
        proofOptions["@context"] = JsonSerializer.SerializeToElement(ZcapContext, ModelSerializerOptions);

        return ConcatenateHashes(
            canonicalizer.Canonicalize(invocationDoc),
            canonicalizer.Canonicalize(proofOptions));
    }

    /// <summary>
    /// Per W3C Data Integrity: SHA-256(proofOptionsCanonical) || SHA-256(documentCanonical).
    /// </summary>
    private static byte[] ConcatenateHashes(byte[] documentCanonical, byte[] proofOptionsCanonical)
    {
        var proofHash = SHA256.HashData(proofOptionsCanonical);
        var docHash = SHA256.HashData(documentCanonical);

        var result = new byte[proofHash.Length + docHash.Length];
        proofHash.CopyTo(result, 0);
        docHash.CopyTo(result, proofHash.Length);
        return result;
    }

    /// <summary>
    /// Round-trips a model object to a string-keyed dictionary of JSON elements,
    /// honoring [JsonPropertyName], [JsonIgnore(WhenWritingNull)], and [JsonConverter]
    /// on the model. The dictionary is what gets fed into the canonicalizer; key order
    /// is irrelevant because JCS sorts alphabetically.
    /// </summary>
    private static Dictionary<string, object> ToFieldDictionary<T>(T value, string? exclude = null)
    {
        var element = JsonSerializer.SerializeToElement(value, ModelSerializerOptions);
        var dict = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var prop in element.EnumerateObject())
        {
            if (exclude is not null && prop.Name == exclude) continue;
            dict[prop.Name] = prop.Value;
        }
        return dict;
    }
}
```

### What each path does — exactly

**JCS path (2020-era embedded-proof convention — DO NOT copy for eddsa-jcs-2022/ecdsa-jcs-2019):**
1. Document is serialized to a `Dictionary<string, object>` of `JsonElement`s via `ToFieldDictionary` (which uses `ZcapJsonOptions.Default`, honoring `[JsonPropertyName]`, null omission, and converters).
2. The proof — minus `proofValue`, excluded **by name** in `ToFieldDictionary(proof, exclude: "proofValue")` — is nested back into the document under key `"proof"`.
3. The single combined object is JCS-canonicalized; those bytes are signed directly (no hashing before signature — the Ed25519/ECDSA primitive hashes internally).
   The signing payload therefore looks like `{...docFields sorted..., "proof":{...proof fields minus proofValue...}}` — pinned byte-for-byte by `CrossLanguageJcsInteropTests.CapabilityJcsPayload_UsesFlatW3cDataIntegrityShape`. Per PRD FR-5, the 2022/2019 JCS suites instead need the same separate-proof-config + hash-concat used on the RDFC path (with `@context` injected into the proof config per the cryptosuite specs).

**RDFC path (spec-correct hash-concat — transfers directly per FR-11):**
1. Proof options = all proof fields except `proofValue`, **plus** `"@context"`: copied verbatim from the document (`capabilityWithoutProof.Context`) on the capability path, or hard-coded `"https://w3id.org/zcap/v1"` on the invocation path (the Invocation model has no `@context`; dataproofs' generalized documents always carry their own).
2. Document (already proof-free) and proof options are RDFC-1.0-canonicalized **separately**.
3. `ConcatenateHashes` — ⚠️ **parameter-name trap**: the signature reads `(documentCanonical, proofOptionsCanonical)` and call sites pass `(canonical(document), canonical(proofOptions))`, but the body emits `SHA256(proofOptions) || SHA256(document)` — proof-config hash FIRST. That ordering is the spec-correct one (vc-di-eddsa/ecdsa: `hashData = proofConfigHash ‖ transformedDocumentHash`). Keep the ordering; fix the naming on port.
4. The 64-byte concatenation is what gets signed (again, no extra outer hash).

**`proofValue` exclusion** happens in exactly one place — the `exclude: "proofValue"` argument to `ToFieldDictionary` — on both paths. At sign time the `Proof` instance carries `ProofValue = string.Empty` (not null; `proofValue` has no `WhenWritingNull` ignore), so name-based exclusion, not null-omission, is what keeps it out of the payload.

**Hash dependency:** `System.Security.Cryptography.SHA256.HashData` — **forbidden in dataproofs src/** (PRD §2.2); replace with `NetCrypto.Hash.Sha256` (and `Sha384` for P-384 suites).

---

## 4. Proof / ProofSet models and JSON converters

### 4.1 `Proof` — `src/ZcapLd.Core/Models/Proof.cs`

2020-era zcap shape; the dataproofs `DataIntegrityProof` (FR-1) reconciles this with net-did's record. Serialization-relevant members:

| Member | JSON name | Null handling | Notes |
|---|---|---|---|
| `string Type` | `type` | always written (defaults `""`) | e.g. `"Ed25519Signature2020"` |
| `string? Created` | `created` | written when non-null | **stored as the verbatim wire string**, never re-formatted — cross-stack JCS byte-equivalence depends on it. `[JsonIgnore] DateTime? CreatedAt => ZcapTimestamps.ParseOrNull(Created)` is the parsed view |
| `string ProofPurpose` | `proofPurpose` | always written | constants: `CapabilityInvocationPurpose`/`CapabilityDelegationPurpose`/`CapabilityRevocationPurpose` |
| `string VerificationMethod` | `verificationMethod` | always written | DID key URI |
| `object[]? CapabilityChain` | `capabilityChain` | `[JsonIgnore(Condition = WhenWritingNull)]` | zcap-specific; entries are id strings + one embedded parent object |
| `string ProofValue` | `proofValue` | always written (non-nullable, defaults `""`) | multibase base58-btc string |
| `InvocationCapability? Capability` | `capability` | WhenWritingNull | zcap-specific |
| `string? InvocationTarget` | `invocationTarget` | WhenWritingNull | zcap-specific |
| `string? CapabilityAction` | `capabilityAction` | WhenWritingNull | zcap-specific |
| `Dictionary<string, JsonElement>? AdditionalProperties` | — | `[JsonExtensionData]` | round-trips unmodeled fields (`domain`, `nonce`, `challenge`, `id`, extensions) verbatim through deserialization AND canonicalization — without it, cross-stack signatures over such proofs fail because fields get silently dropped |

`Created` timestamps generated locally use `ZcapTimestamps.Format` (`src/ZcapLd.Core/Models/ZcapTimestamps.cs`): `"yyyy-MM-ddTHH:mm:ss.ffffffZ"` — 6-digit microsecond UTC ISO-8601; `Parse` accepts any ISO-8601 shape via `DateTimeOffset.Parse(..., InvariantCulture).UtcDateTime`. Note VC-DI 1.0 expects `XMLSCHEMA11-2 dateTimeStamp`; keep verbatim-string storage, but the canonical emit format is worth revisiting against W3C test vectors (they typically use second precision `...Z`).

### 4.2 `ProofSet` — `src/ZcapLd.Core/Models/ProofSet.cs`

Immutable wrapper over `Proof[]` modeling the string-or-array duality of `proof`:
- `[JsonConverter(typeof(ProofSetJsonConverter))]` on the type.
- `IsArrayForm` tracks the original wire shape; a single proof round-trips as a **bare object**, an array round-trips as an **array** (even with one element). Shape preservation is for round-trip fidelity only — the signed bytes always canonicalize a single `Proof` (proof-set semantics: each proof verified independently over the document with ALL proofs removed).
- Factories: `FromSingle(Proof)` (object form), `FromValues(IEnumerable<Proof>, bool asArray = true)` (throws on null/empty/contains-null).
- Accessors: `Values` (`IReadOnlyList<Proof>`), `Count`, `Primary` (first), plus zcap-specific `DelegationProofs()` / `FirstDelegationProof()` / `FirstDelegationProofWithChain()` (ordinal `proofPurpose == "capabilityDelegation"` filters).
- Implicit conversions: `Proof → ProofSet` (object form) and `Proof[] → ProofSet` (array form).

### 4.3 `ProofSetJsonConverter` — `src/ZcapLd.Core/Cryptography/ProofSetJsonConverter.cs` (`internal sealed`)

- **Read:** `StartObject` → deserialize single `Proof` → `FromSingle`; `StartArray` → each entry MUST be an object (else `JsonException`), empty array → `JsonException` ("proof array MUST contain at least one proof."); any other token → `JsonException`. Null entry deserialization → `JsonException`.
- **Write:** dispatches on `IsArrayForm`; each `Proof` goes through normal STJ machinery so `[JsonExtensionData]` and `WhenWritingNull` are honored.

### 4.4 `ZcapJsonOptions` — `src/ZcapLd.Core/Cryptography/ZcapJsonOptions.cs`

The single shared `JsonSerializerOptions` used by sign-time canonicalization AND wire (de)serialization — sharing is the contract that makes signed bytes equal wire bytes:

```csharp
var options = new JsonSerializerOptions
{
    WriteIndented = false,
    PropertyNamingPolicy = null,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
};
options.Converters.Add(new CaveatJsonConverter(CaveatTypeRegistry.Default));
```

Settings rationale (from the file's doc comment): whitespace-free for JCS; `WhenWritingNull` keeps absent optionals off the wire (strict cross-language parsers reject empty arrays/nulls); `UnsafeRelaxedJsonEscaping` per RFC 8785 §3.2.2.2. The `CaveatJsonConverter` is zcap-specific (polymorphic caveats) — dataproofs doesn't need it, but the **pattern** (one options singleton shared by signing and wire emit, converters registered once) is the thing to port. Related converters that demonstrate the string-or-array / string-or-object handling pattern:
- `ControllerSetJsonConverter` (`controller`: bare string vs array, shape-preserving) — `src/ZcapLd.Core/Cryptography/ControllerSetJsonConverter.cs`.
- `InvocationCapabilityJsonConverter` (`capability`: root-id string vs full embedded object, shape-preserving; rejects other tokens) — `src/ZcapLd.Core/Cryptography/InvocationCapabilityJsonConverter.cs`. This pattern maps onto FR-1's `previousProof` (string or set).

### 4.5 Document models (for the "generalize to arbitrary documents" adaptation)

`Capability` (`src/ZcapLd.Core/Models/Capability.cs`): `@context` is typed `object` (`string` for roots, `object[]` for delegated; after deserialization it may be a `JsonElement` — see `CapabilityService.IsStringContext/IsArrayContext` for the dual-type handling). Carries `[JsonExtensionData] AdditionalProperties` like `Proof`. `Invocation` (`src/ZcapLd.Core/Models/Invocation.cs`): `id` (defaults `urn:uuid:{Guid.NewGuid()}`), `capability`, `capabilityAction`, `invocationTarget`, `proof` (single `Proof`, WhenWritingNull). In dataproofs both collapse into "arbitrary JSON-LD document" (FR-2) — the `CloneXxxWithoutProof` methods become a generic "remove `proof` member" operation on the document representation.

---

## 5. Signing flow, `SignatureVerifier`, `SignatureResult`

### 5.1 `SignatureResult` — `src/ZcapLd.Core/Models/SignatureResult.cs` (full)

```csharp
namespace ZcapLd.Core.Models;

/// <summary>
/// Result of a signing operation, bundling the raw signature bytes with
/// the signature type string (e.g. "Ed25519Signature2020").
/// This allows different providers to declare their algorithm contextually.
/// </summary>
public record SignatureResult(byte[] Signature, string SignatureType);
```

Produced by `IDidSigner.SignAsync(string did, byte[] data)` (`src/ZcapLd.Core/Services/IDidSigner.cs`) — the non-exporting-key abstraction ("private key never leaves the provider, enabling HSM, Key Vault, and cloud KMS"; no default impl ships). This is the precedent for routing through NetCrypto `ISigner` (FR-2/AC-8). `SigningService.ValidateSignatureType` ordinally compares `result.SignatureType` against the suite's `ProofType` and throws `CryptographicException` on mismatch — a cheap algorithm-confusion guard worth keeping (compare against `cryptosuite` id in dataproofs).

### 5.2 How `proofValue` is produced — `src/ZcapLd.Core/Services/SigningService.cs` (signing pipeline excerpt, lines 99–123)

```csharp
var capabilityWithoutProof = ProofSigningPayloadBuilder.CloneCapabilityWithoutProof(capability);
var suite = await ResolveSuiteForDidAsync(signerDid);          // resolver → ResolvedKey.KeyType → ICryptoSuiteProvider.GetByKeyType
var canonicalizer = ResolveCanonicalizer(suite);               // IDocumentCanonicalizerProvider.GetByMethod(suite.CanonicalizationMethod)
var verificationMethod = await _resolver.GetVerificationMethodAsync(signerDid);
var created = ZcapTimestamps.Format(createdOverride ?? DateTime.UtcNow);

var proof = new Proof
{
    Type = suite.ProofType,
    Created = created,
    ProofPurpose = proofPurpose,
    VerificationMethod = verificationMethod,
    CapabilityChain = capabilityChain ?? Array.Empty<object>(),
    ProofValue = string.Empty                                   // placeholder; excluded by name from payload
};

var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(
    capabilityWithoutProof, proof, canonicalizer);
var result = await _signer.SignAsync(signerDid, canonicalBytes);
ValidateSignatureType(result.SignatureType, proofType);
proof.ProofValue = MultibaseCodec.Encode(result.Signature);     // base58-btc multibase, 'z' prefix

return proof;
```

The default suite/canonicalizer providers (`SigningService.CreateDefaultSuiteProvider` / `CreateDefaultCanonicalizerProvider`) register `CryptoSuite.Ed25519()`, `CryptoSuite.P256()`, and `JcsDocumentCanonicalizer` only — RDFC is opt-in by registering `RdfcDocumentCanonicalizer` plus an RDFC-flavored suite.

### 5.3 `SignatureVerifier` — `src/ZcapLd.Core/Cryptography/SignatureVerifier.cs` (full logic)

Static utility (the low-level "does this signature verify" check; the full policy engine is `VerificationService`):

```csharp
public static bool VerifyCapabilitySignature(
    Capability capability, byte[] publicKey, ICryptoSuite suite, IDocumentCanonicalizer? canonicalizer = null)
{
    if (capability.Proof == null)
        return false;

    // A delegated zcap's proof may be an array. Mirror VerificationService's any-verifies
    // semantics: succeed if ANY capabilityDelegation proof validates against the supplied
    // key. Fall back to all proofs when none declare the delegation purpose (non-standard
    // inputs). A single malformed proof must not abort evaluation of the rest.
    var candidates = capability.Proof.DelegationProofs().ToList();
    if (candidates.Count == 0)
        candidates = capability.Proof.Values.ToList();

    foreach (var proof in candidates)
    {
        try
        {
            var capabilityForVerification = ProofSigningPayloadBuilder.CloneCapabilityWithoutProof(capability);
            var canonicalizedData = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(
                capabilityForVerification, proof, canonicalizer);

            var signature = MultibaseCodec.Decode(proof.ProofValue);

            if (suite.Verify(canonicalizedData, signature, publicKey))
                return true;
        }
        catch
        {
            // Try the next candidate proof.
        }
    }
    return false;
}

public static bool VerifyInvocationSignature(
    Invocation invocation, byte[] publicKey, ICryptoSuite suite, IDocumentCanonicalizer? canonicalizer = null)
{
    if (invocation.Proof == null)
        return false;
    try
    {
        var invocationForVerification = ProofSigningPayloadBuilder.CloneInvocationWithoutProof(invocation);
        var canonicalizedData = ProofSigningPayloadBuilder.CanonicalizeInvocationPayload(
            invocationForVerification, invocation.Proof, canonicalizer);
        var signature = MultibaseCodec.Decode(invocation.Proof.ProofValue);
        return suite.Verify(canonicalizedData, signature, publicKey);
    }
    catch
    {
        return false;
    }
}

public static bool ValidateProofStructure(Proof proof)
{
    return !string.IsNullOrEmpty(proof.Type) &&
           !string.IsNullOrEmpty(proof.ProofPurpose) &&
           !string.IsNullOrEmpty(proof.VerificationMethod) &&
           !string.IsNullOrEmpty(proof.ProofValue) &&
           !string.IsNullOrEmpty(proof.Created);
}
```

Checks performed: (1) proof present; (2) document cloned without proof; (3) payload rebuilt identically to sign time; (4) `proofValue` multibase-decoded; (5) `suite.Verify` over raw bytes. Proof-set semantics: each candidate proof is verified independently against the proof-free document; one bad proof doesn't abort the rest. Returns plain `bool` (no detail) — the richer path in `VerificationService.VerifyDelegationProofAsync` (`src/ZcapLd.Core/Services/VerificationService.cs` ~lines 436–535) additionally: checks proof `created` freshness, resolves the key from `proof.verificationMethod`, looks up the suite via `GetByProofType(proof.Type)` (fail → `InvalidSignature` "Unsupported delegation proof type"), enforces `KeyTypeMatches` (line 861: `string.Equals(suite.KeyType, resolvedKey.KeyType, StringComparison.Ordinal)`), decodes via `DecodeProofValue` (line 279: wraps `MultibaseCodec.Decode`, converting `CryptographicException`/`ArgumentException` into `CapabilityValidationException("Malformed or unsupported proofValue.")`), and classifies exceptions into `InvalidDelegation` (attacker-drivable parse/validation failures) vs `CouldNotVerify` (infrastructure faults) — a fail-closed taxonomy worth carrying into FR-2's verify-side result type.

---

## 6. `CachedContextLoader` (→ becomes `CachingNetworkDocumentLoader`) — `src/ZcapLd.Core/Cryptography/CachedContextLoader.cs` (FULL)

```csharp
using System.Reflection;
using VDS.RDF.JsonLd;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Serves known W3C JSON-LD contexts from embedded assembly resources,
/// avoiding HTTP fetches in restricted/offline environments.
/// Falls back to the default HTTP loader for unknown context URIs.
/// </summary>
internal static class CachedContextLoader
{
    private static readonly Dictionary<string, string> EmbeddedContexts;

    static CachedContextLoader()
    {
        var assembly = typeof(CachedContextLoader).Assembly;

        // Map: context URL → embedded resource name
        var mapping = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["https://w3id.org/zcap/v1"] =
                "ZcapLd.Core.Cryptography.Contexts.zcap-v1.jsonld",
            ["https://w3id.org/security/suites/ed25519-2020/v1"] =
                "ZcapLd.Core.Cryptography.Contexts.ed25519-2020-v1.jsonld",
        };

        EmbeddedContexts = new Dictionary<string, string>(mapping.Count, StringComparer.Ordinal);

        foreach (var (url, resourceName) in mapping)
        {
            using var stream = assembly.GetManifestResourceStream(resourceName)
                ?? throw new InvalidOperationException(
                    $"Embedded JSON-LD context resource '{resourceName}' not found in assembly.");

            using var reader = new StreamReader(stream);
            EmbeddedContexts[url] = reader.ReadToEnd();
        }
    }

    /// <summary>
    /// Document loader callback for <see cref="JsonLdProcessorOptions.DocumentLoader"/>.
    /// Returns cached embedded contexts for known URLs, falls back to HTTP for others.
    /// </summary>
    public static RemoteDocument LoadDocument(Uri uri, JsonLdLoaderOptions options)
    {
        if (EmbeddedContexts.TryGetValue(uri.AbsoluteUri, out var cachedJson))
        {
            return new RemoteDocument
            {
                Document = Newtonsoft.Json.Linq.JToken.Parse(cachedJson),
                DocumentUrl = uri
            };
        }

        // Fallback: HTTP fetch for unknown contexts
        return DefaultDocumentLoader.LoadJson(uri, options);
    }
}
```

Behavior: **embedded-resources-first, network-fallback, no negative caching, no caching of fetched documents** (a fetched URI is re-fetched every parse), no offline/strict mode, static (not injectable). Embedded contexts (csproj: `<EmbeddedResource Include="Cryptography/Contexts/*.jsonld" />`): `zcap-v1.jsonld` and `ed25519-2020-v1.jsonld` only. Both are `@protected` term definitions. For dataproofs the embedded set must change to the VC/Data-Integrity contexts (`https://www.w3.org/ns/credentials/v2`, `https://w3id.org/security/data-integrity/v2`, multikey, etc.), and per the name `CachingNetworkDocumentLoader` it should actually cache network results, be instance-based/injectable, and ideally support an offline-only mode (network fetch during signature verification is an SSRF/availability hazard). Note the Newtonsoft `JToken` in the signature — this loader is dotNetRDF-coupled and so belongs in the `Rdfc` package, not `Core`.

---

## 7. `MultibaseCodec` (REFERENCE ONLY — NetCid replaces it) — `src/ZcapLd.Core/Cryptography/MultibaseCodec.cs`

Behavior contract that NetCid usage in dataproofs must reproduce:
- `Encode(byte[] data)` → `NetCid.Multibase.Encode(data, MultibaseEncoding.Base58Btc)` → `"z" + base58btc(data)`. Throws `ArgumentException` for null/**empty** input; wraps any NetCid failure in `ZcapLd.Core.Exceptions.CryptographicException("Failed to encode data", ex)`.
- `Decode(string encoded)` → requires the string to start with `'z'` (explicit pre-check throwing `CryptographicException("Multibase string must start with 'z' prefix")` — i.e. **only base58-btc proofValues are accepted**, other multibase prefixes are rejected), then `NetCid.Multibase.Decode(encoded)`; null/empty → `ArgumentException`; other failures wrapped in `CryptographicException("Failed to decode multibase string", ex)`.
- NetCid version in use: 1.5.0 (dataproofs should use current NetCid; `Multibase.Encode/Decode` API is the same family `net-cid` ships alongside `Multikey`).
- Call sites that the port re-routes straight to NetCid: `SigningService` lines 121/255 (`proof.ProofValue = MultibaseCodec.Encode(result.Signature)`), `SignatureVerifier` lines 45/85, `VerificationService.DecodeProofValue` line 283.

---

## 8. Tests covering this machinery (paths + high-level assertions)

All under `/Users/moises/Projects/zcap-dotnet/tests/ZcapLd.Core.Tests/`. Per PRD §1.4 these **guide** the port (conformance is pinned to W3C AC-1 vectors instead), but several are direct templates:

| Path | What it asserts |
|---|---|
| `Cryptography/CryptoSuiteTests.cs` | Suite identifier triples (proof type / key type / context URL) for Ed25519 + P256; sign/verify round-trips; wrong-key and tampered-signature rejection; **`P256_Sign_ProducesIeeeP1363WireFormat_NotDer`** (64-byte signature, would be DER without the format-aware overload); ctor null-arg throws |
| `Cryptography/CryptoSuiteProviderTests.cs` | Registry lookup by proof type, miss → null, null/empty → null, duplicate registration replaces, `Register(null)` throws |
| `Cryptography/DocumentCanonicalizerProviderTests.cs` | Same registry semantics for canonicalizers; JCS and RDFC independently registered |
| `Cryptography/JsonCanonicalizerTests.cs` | JCS determinism, alphabetical key sort, UTF-8 output, no whitespace, null-property exclusion, `RemoveProofField` behavior (top-level only / arrays preserved / sorts) |
| `Cryptography/JcsDocumentCanonicalizerTests.cs` | `Method == "JCS"`, determinism, sorting, delegation to `JsonCanonicalizer`, null throws |
| `Cryptography/RdfcDocumentCanonicalizerTests.cs` | `Method == "RDFC-1.0"`, JSON-LD → N-Quads output shape, determinism, property-order independence, raw-string input accepted, output differs from JCS |
| `Cryptography/RdfcComplianceTests.cs` | **4 official W3C rdf-canon vectors run directly against `VDS.RDF.RdfCanonicalizer`** over N-Quads input (test002 no-blank-node passthrough, test003 `_:e0`→`_:c14n0` relabel, test006 lexicographic quad sort, empty input → empty output). Template for the dataproofs `Rdfc` package's W3C-vector harness |
| `Cryptography/SignatureVerifierTests.cs` | Signed invocation verifies via `SignatureVerifier`; tampering with proof *metadata* (not just document) breaks the signature — proves proof options are inside the signed payload |
| `Cryptography/MultibaseCodecTests.cs` | `z`-prefixed encode, round-trip, invalid-prefix/null/empty error cases (+ two stray JCS determinism tests) |
| `Integration/RdfcCanonicalizeIntegrationTests.cs` | `ProofSigningPayloadBuilder` with JCS produces the expected flat payload; **RDFC payload differs from JCS payload for same inputs** (proves the dual-path dispatch); RDFC determinism across calls; `ICryptoSuite.CanonicalizationMethod` defaults to `"JCS"` |
| `Integration/RdfcEndToEndTests.cs` | Full pipeline with `CanonicalizationMethod = "RDFC-1.0"`: root create+invoke, single/multi-level delegation chains verify, tampered capability rejected. Shows the wiring: register both canonicalizers + RDFC suite, share providers between `SigningService` and `VerificationService` |
| `Compliance/CrossLanguageJcsInteropTests.cs` | **Known-answer byte-exact canonical payloads** (the only drift-catcher: in-process round-trips can't catch shape bugs). Pins: flat W3C shape incl. exact expected JCS string; `proofValue` never in payload; no wrapper shape; sign-time bytes == wire bytes (incl. derived caveats, controller arrays, proof arrays/single, unmodeled extension fields on both `Proof` and `Capability`); `created` preserved verbatim regardless of input shape; `ZcapTimestamps.Format` 6-digit-microsecond UTC. **This known-answer technique is the single most valuable test pattern to port** |
| `Models/ProofSetTests.cs` | ProofSet shape preservation (object vs array round-trip), empty/null rejection, delegation-proof filtering, implicit conversions |
| `Compliance/NormativeUnitComplianceTests.cs`, `NormativeIntegrationComplianceTests.cs`, `DelegatedInvocationComplianceTests.cs`, `ComplianceTestFixture.cs` | ZCAP-LD-spec normative requirements (chain shape, root invocation, revocation) — zcap-domain; guide-only |
| `Cryptography/CaveatJsonConverterTests.cs`, `Models/ControllerSetTests.cs` | Polymorphic/shape-preserving converter behavior — pattern reference for `previousProof` string-or-set handling |

---

## 9. dotNetRDF quirks summary (for the `Rdfc` package)

1. **Version:** `dotNetRdf.Core` 3.5.1 (netstandard2.0). Canonicalization entry point: `VDS.RDF.RdfCanonicalizer` (namespace `VDS.RDF`, NOT `VDS.RDF.Canonicalization`), ctor `RdfCanonicalizer(string hashAlgorithm = "SHA256")`, method `Canonicalize(ITripleStore)` → `RdfCanonicalizer.CanonicalizedRdfDataset` (`SerializedNQuads` string property; `InputDataset`/`OutputDataset`/`IssuedIdentifiersMap` public fields).
2. **Newtonsoft coupling:** the JSON-LD subsystem (`JsonLdParser`, `JsonLdProcessorOptions`, `RemoteDocument`) is built on `Newtonsoft.Json` 13.0.4 (`JToken`). Documents must cross from System.Text.Json as strings; loader callbacks hand back `JToken`s. This is contained today inside `RdfcDocumentCanonicalizer` + `CachedContextLoader` — keep that containment inside `DataProofsDotnet.Rdfc` (sole dotNetRDF reference per PRD §2.2).
3. **JSON-LD parse path:** `new TripleStore()` → `new JsonLdParser(new JsonLdProcessorOptions { DocumentLoader = ... })` → `parser.Load(store, new StringReader(json))`. No other processor options are configured — default JSON-LD 1.1 processing mode, undefined terms silently dropped (see risks).
4. **N-Quads in vectors:** `RdfcComplianceTests` uses `VDS.RDF.Parsing.NQuadsParser().Load(store, StringReader)` to feed raw-N-Quads W3C vectors, bypassing JSON-LD — useful for the rdf-canon vector harness.

---

## 10. Porting map (zcap type → dataproofs home) and gotchas checklist

| zcap source | dataproofs target | Adaptation |
|---|---|---|
| `ICryptoSuiteProvider`/`CryptoSuiteProvider` | `Core` suite registry (FR-4) | re-key by `cryptosuite` string; `GetByKeyType` becomes unnecessary or maps via Multikey codes |
| `ICryptoSuite`/`CryptoSuite` | `Core` cryptosuite abstraction (FR-4/5) + `Rdfc` suites (FR-11) | replace raw-key `Sign(byte[],byte[])` with NetCrypto `ISigner` (async, `CancellationToken`); keep IeeeP1363 for P-256/P-384; identifiers → `eddsa-jcs-2022`/`ecdsa-jcs-2019`/`eddsa-rdfc-2022`/`ecdsa-rdfc-2019`, `type` always `DataIntegrityProof`, context → `https://w3id.org/security/data-integrity/v2` |
| `IDocumentCanonicalizer`(+Provider) | `Core` | unchanged mechanics; JCS impl in `Core`, RDFC impl in `Rdfc` |
| `JsonCanonicalizer` | **superseded by NetCid JCS** (PRD FR-5) | keep `UnsafeRelaxedJsonEscaping` lesson; do not inherit culture-sort/number/null gaps |
| `RdfcDocumentCanonicalizer` | `Rdfc` | transfers directly; add hash-algorithm parameter (SHA-384 for P-384); make loader injectable |
| `ProofSigningPayloadBuilder` RDFC path | `Core` proof pipeline (FR-2) hash step | transfers; generalize document type; `SHA256.HashData` → NetCrypto `Hash.Sha256/Sha384`; **keep proofConfigHash-first ordering; fix misleading param names** |
| `ProofSigningPayloadBuilder` JCS path | ⚠️ replaced | 2022/2019 JCS suites use separate-proof-config + hash-concat (same mechanic as RDFC path, JCS canonicalizer, `@context` injected into proof config per spec) |
| `Proof`/`ProofSet` + converters | `Core` `DataIntegrityProof` model (FR-1) | drop zcap fields (`capabilityChain`, `capability`, `invocationTarget`, `capabilityAction`); add `cryptosuite`, `expires`, `challenge`, `domain`, `nonce`, `previousProof`, `id`; keep `[JsonExtensionData]`, verbatim `created`, shape-preserving set converter, `WhenWritingNull` everywhere |
| `ZcapJsonOptions` | `Core` JSON options singleton | same settings minus caveat converter |
| `SignatureVerifier` + `SignatureResult` | FR-2 verify algorithm | generalize; keep per-proof independence, name-based `proofValue` exclusion, fail-closed exception taxonomy; surface structured results instead of bool |
| `CachedContextLoader` | `Rdfc` `CachingNetworkDocumentLoader` | new embedded context set (VC v2 / data-integrity v2 / multikey); add real caching of fetched docs + offline mode; injectable instance |
| `MultibaseCodec` | **not ported** | NetCid `Multibase` direct (base58-btc, `z`-prefix enforcement on decode) |
| `IDidSigner`/`IDidResolver`/`ResolvedKey` | NetCrypto `ISigner` / FR-7 `IVerificationMethodResolver` | keep ordinal key-type binding idea (Issue #68) translated to multikey/JWK key-type checks |
