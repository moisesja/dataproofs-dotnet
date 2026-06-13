using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

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
