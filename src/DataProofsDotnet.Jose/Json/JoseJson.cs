using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using System.Text.Unicode;
using DataProofsDotnet.Jose.Encryption;
using DataProofsDotnet.Jose.Signing;

namespace DataProofsDotnet.Jose.Json;

/// <summary>
/// Shared <see cref="JsonSerializerOptions"/> for JOSE model serialization. Ported from
/// didcomm-dotnet <c>DidComm.Json.DidCommJson</c> (PRD §1.4 item 2), minus the
/// DIDComm-specific epoch-seconds converter. Metadata is source-generated
/// (<see cref="JoseJsonContext"/>, issue #27); serializer calls use the typed accessors below.
/// </summary>
internal static class JoseJson
{
    /// <summary>Default options for serializing/deserializing JOSE DTOs (headers, JWKs).</summary>
    public static readonly JsonSerializerOptions Default = CreateDefault();

    /// <summary>Metadata for <see cref="JwsProtectedHeader"/>, bound to <see cref="Default"/>.</summary>
    public static readonly JsonTypeInfo<JwsProtectedHeader> JwsHeaderTypeInfo = TypeInfo<JwsProtectedHeader>();

    /// <summary>Metadata for <see cref="JweProtectedHeader"/>, bound to <see cref="Default"/>.</summary>
    public static readonly JsonTypeInfo<JweProtectedHeader> JweHeaderTypeInfo = TypeInfo<JweProtectedHeader>();

    /// <summary>Metadata for <see cref="Jwk"/>, bound to <see cref="Default"/>.</summary>
    public static readonly JsonTypeInfo<Jwk> JwkTypeInfo = TypeInfo<Jwk>();

    /// <summary>Metadata for <see cref="string"/>, bound to <see cref="Default"/>.</summary>
    public static readonly JsonTypeInfo<string> StringTypeInfo = TypeInfo<string>();

    /// <summary>
    /// Parse options that reject duplicate member names, for the raw <see cref="JsonDocument"/> /
    /// <see cref="System.Text.Json.Nodes.JsonNode"/> parses (JWS/JWE structure, JWT claims) that
    /// don't flow through <see cref="Default"/>. Mirrors <c>AllowDuplicateProperties = false</c>
    /// on <see cref="Default"/> — a repeated member is a parser-differential smuggling vector,
    /// so fail closed.
    /// </summary>
    public static readonly JsonDocumentOptions StrictDocument = new() { AllowDuplicateProperties = false };

    /// <summary>
    /// Reject JSON text whose strings cannot be read back as .NET strings, before it reaches a
    /// JSON parser: octets that are not well-formed UTF-8, and JSON escapes for an unpaired
    /// UTF-16 surrogate.
    /// </summary>
    /// <remarks>
    /// RFC 7515 §5.2 step 3, RFC 7516 §5.2 step 3 and RFC 7519 §7.2 step 10 all require that a
    /// base64url-decoded header or claims set "is a UTF-8-encoded representation of a completely
    /// valid JSON object", and RFC 8259 §8.1 requires JSON exchanged between systems to be UTF-8.
    /// Neither <see cref="JsonDocument"/> nor <see cref="JsonSerializer"/> enforces it: the reader
    /// validates structure, not encoding, and only transcodes a string when a caller asks for it.
    /// An unknown member name lands in a <c>[JsonExtensionData]</c> bag through the lossy
    /// <c>Encoding.UTF8</c> decoder (invalid bytes become U+FFFD), a string <em>value</em> in that
    /// bag is cloned as a raw <see cref="JsonElement"/> and never transcoded, and a lazily
    /// materialised <see cref="System.Text.Json.Nodes.JsonNode"/> throws
    /// <see cref="InvalidOperationException"/> — not <see cref="JsonException"/> — at first
    /// access (issue #28).
    /// <para>
    /// A JSON escape for an unpaired surrogate (<c>\uD800</c>, <c>\uDC00</c>, <c>\uD800A</c>) is
    /// the same fault one layer up. Those bytes are valid UTF-8 and RFC 8259 §8.2 lets the grammar
    /// contain them, but the string they denote is not Unicode text: RFC 8259 §8.2 calls the
    /// receiver's behaviour "unpredictable" and RFC 7493 (I-JSON) §2.1 forbids them outright.
    /// System.Text.Json accepts them at parse time and throws <see cref="InvalidOperationException"/>
    /// on the deferred transcode — from <c>GetString()</c>, from the member-name comparison in
    /// <c>TryGetProperty</c> / <c>EnumerateObject</c> / <see cref="System.Text.Json.Nodes.JsonObject"/>,
    /// and from <c>ToJsonString()</c> — anywhere from the parser itself to a consumer reading a
    /// claim long after verification succeeded (issue #30).
    /// </para>
    /// <para>
    /// One pass closes both, so after this call every member name and string in the text reads
    /// back successfully, through any API. Unescaped tokens need no transcode: validated UTF-8
    /// cannot encode a surrogate. A reader error is reported as invalid JSON rather than left for
    /// the parser that follows: the reader's defaults accept exactly the grammar of every parser in
    /// this package (no comments, no trailing commas, depth 64, no BOM), and failing here keeps the
    /// check fail-closed should a parser's options ever become more lenient than the reader's.
    /// </para>
    /// </remarks>
    /// <param name="utf8Json">The JSON text as UTF-8 octets.</param>
    /// <param name="what">What the text is, for the exception message (e.g. "JWS protected header").</param>
    /// <exception cref="MalformedJoseException">
    /// When <paramref name="utf8Json"/> is not valid UTF-8, is not valid JSON, or contains a JSON
    /// escape for an unpaired UTF-16 surrogate.
    /// </exception>
    public static void RequireTranscodableJson(ReadOnlySpan<byte> utf8Json, string what)
    {
        if (!Utf8.IsValid(utf8Json))
            throw new MalformedJoseException($"{what} is not valid UTF-8.");

        var reader = new Utf8JsonReader(utf8Json);
        try
        {
            while (reader.Read())
            {
                if (reader.TokenType is JsonTokenType.PropertyName or JsonTokenType.String && reader.ValueIsEscaped)
                    _ = reader.GetString();
            }
        }
        catch (JsonException ex)
        {
            throw new MalformedJoseException($"{what} is not valid JSON.", ex);
        }
        catch (InvalidOperationException ex)
        {
            throw new MalformedJoseException($"{what} contains an unpaired UTF-16 surrogate escape.", ex);
        }
    }

    /// <summary>
    /// Parse caller-supplied JSON text — a JWS or JWE JSON serialization — into a
    /// <see cref="JsonDocument"/> that rejects duplicate members, after
    /// <see cref="RequireTranscodableJson"/> has passed it.
    /// </summary>
    /// <remarks>
    /// The check must run before the parse, not after it: the duplicate-member validation inside
    /// <see cref="JsonDocument.Parse(ReadOnlyMemory{byte}, JsonDocumentOptions)"/> transcodes every
    /// member name to compare them, and throws <see cref="InvalidOperationException"/> on an
    /// unpaired-surrogate escape (issue #30). The text is transcoded strictly, because a .NET string
    /// that is not well-formed UTF-16 (a lone surrogate <em>character</em>, not an escape) cannot
    /// come from decoding wire bytes — .NET substitutes U+FFFD — only from a caller's own text, and
    /// must still fail through the documented contract (issue #28).
    /// </remarks>
    /// <param name="json">The JSON text.</param>
    /// <param name="what">What the text is, for the exception message ("JWS" or "JWE").</param>
    /// <exception cref="MalformedJoseException">
    /// When <paramref name="json"/> is not well-formed UTF-16, is not valid JSON (including a
    /// duplicate member), or contains a JSON escape for an unpaired UTF-16 surrogate.
    /// </exception>
    public static JsonDocument ParseStrictDocument(string json, string what)
    {
        byte[] utf8;
        try
        {
            utf8 = StrictUtf8.GetBytes(json);
        }
        catch (EncoderFallbackException ex)
        {
            throw new MalformedJoseException($"{what} is not valid JSON text: the string is not well-formed UTF-16.", ex);
        }

        RequireTranscodableJson(utf8, what);

        try
        {
            return JsonDocument.Parse(utf8, StrictDocument);
        }
        catch (JsonException ex)
        {
            throw new MalformedJoseException($"{what} is not valid JSON.", ex);
        }
    }

    /// <summary>UTF-8 that throws on a lone surrogate instead of substituting U+FFFD.</summary>
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    // GetTypeInfo(Type) is AOT-safe: it resolves through Default's resolver, the source-generated
    // context, and returns metadata bound to Default's wire settings.
    private static JsonTypeInfo<T> TypeInfo<T>() => (JsonTypeInfo<T>)Default.GetTypeInfo(typeof(T));

    private static JsonSerializerOptions CreateDefault()
    {
        var options = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false,
            PropertyNameCaseInsensitive = false,
            // Reject duplicate JSON member names rather than silently taking the last (the .NET 10
            // default is to allow them). JOSE headers are a fixed namespace; a repeated `alg` /
            // `enc` / `kid` is a parser-differential smuggling vector, so fail closed.
            AllowDuplicateProperties = false,
            // Use the relaxed JSON encoder so characters like '+' inside media types and
            // algorithm names ("ECDH-ES+A256KW") emit as the literal character rather than the
            // + JavaScript-safe escape. The JOSE spec vectors carry the literal form; the
            // deterministic-JSON bytes feeding the JWS signing input / JWE AAD must match.
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            // Source-generated metadata only: these options serialize this package's own DTOs and
            // nothing else, so there is no reflection fallback to keep (unlike the public
            // DataProofsJsonOptions.Default).
            TypeInfoResolver = JoseJsonContext.Default,
        };
        options.MakeReadOnly();
        return options;
    }
}
