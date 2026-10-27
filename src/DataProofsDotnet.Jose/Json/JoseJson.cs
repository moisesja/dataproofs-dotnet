using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Unicode;

namespace DataProofsDotnet.Jose.Json;

/// <summary>
/// Shared <see cref="JsonSerializerOptions"/> for JOSE model serialization. Ported from
/// didcomm-dotnet <c>DidComm.Json.DidCommJson</c> (PRD §1.4 item 2), minus the
/// DIDComm-specific epoch-seconds converter.
/// </summary>
internal static class JoseJson
{
    /// <summary>Default options for serializing/deserializing JOSE DTOs (headers, JWKs).</summary>
    public static readonly JsonSerializerOptions Default = CreateDefault();

    /// <summary>
    /// Parse options that reject duplicate member names, for the raw <see cref="JsonDocument"/> /
    /// <see cref="System.Text.Json.Nodes.JsonNode"/> parses (JWS/JWE structure, JWT claims) that
    /// don't flow through <see cref="Default"/>. Mirrors <c>AllowDuplicateProperties = false</c>
    /// on <see cref="Default"/> — a repeated member is a parser-differential smuggling vector,
    /// so fail closed.
    /// </summary>
    public static readonly JsonDocumentOptions StrictDocument = new() { AllowDuplicateProperties = false };

    /// <summary>
    /// Reject decoded octets that are not well-formed UTF-8 before they reach a JSON parser.
    /// </summary>
    /// <remarks>
    /// RFC 7515 §5.2 step 3, RFC 7516 §5.2 step 3 and RFC 7519 §7.2 step 10 all require that a
    /// base64url-decoded header or claims set "is a UTF-8-encoded representation of a completely
    /// valid JSON object", and RFC 8259 §8.1 requires JSON exchanged between systems to be UTF-8. Neither
    /// <see cref="JsonDocument"/> nor <see cref="JsonSerializer"/> enforces it: the reader
    /// validates structure, not encoding, and only transcodes a string when a caller asks for it.
    /// An unknown member name lands in a <c>[JsonExtensionData]</c> bag through the lossy
    /// <c>Encoding.UTF8</c> decoder (invalid bytes become U+FFFD), a string <em>value</em> in that
    /// bag is cloned as a raw <see cref="JsonElement"/> and never transcoded, and a lazily
    /// materialised <see cref="System.Text.Json.Nodes.JsonNode"/> throws
    /// <see cref="InvalidOperationException"/> — not <see cref="JsonException"/> — at first
    /// access. Validating the octets once, up front, closes all three paths for invalid octets and
    /// keeps every decoder's documented <see cref="MalformedJoseException"/> contract for that input
    /// (issue #28).
    /// <para>
    /// It does <b>not</b> cover a JSON escape for an unpaired surrogate (<c>\uD800</c>). Those six
    /// bytes are valid UTF-8 and the reader accepts them, so the lazy transcode still throws
    /// <see cref="InvalidOperationException"/> when the string is read. That class is a known 1.4.0
    /// limitation, tracked in issue #30.
    /// </para>
    /// </remarks>
    /// <param name="utf8">The decoded octets.</param>
    /// <param name="what">What the octets are, for the exception message (e.g. "JWS protected header").</param>
    /// <exception cref="MalformedJoseException">When <paramref name="utf8"/> is not valid UTF-8.</exception>
    public static void RequireUtf8(ReadOnlySpan<byte> utf8, string what)
    {
        if (!Utf8.IsValid(utf8))
            throw new MalformedJoseException($"{what} is not valid UTF-8.");
    }

    private static JsonSerializerOptions CreateDefault()
    {
        return new JsonSerializerOptions
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
        };
    }
}
