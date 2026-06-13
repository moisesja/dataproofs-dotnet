using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using DataProofsDotnet.Jose.Json;

namespace DataProofsDotnet.Jose.Signing;

/// <summary>
/// DTO for the JWS protected header. Carries <c>alg</c> (the JOSE signing algorithm),
/// <c>kid</c> (the signer key identifier), <c>typ</c>, plus an extension-data bag so unknown
/// header members survive a parse→re-encode round-trip. Ported from didcomm-dotnet
/// <c>DidComm.Jose.Signing.JwsProtectedHeader</c> (PRD §1.4 item 2).
/// </summary>
internal sealed class JwsProtectedHeader
{
    [JsonPropertyName("alg")]
    public string Alg { get; set; } = string.Empty;

    [JsonPropertyName("kid")]
    public string Kid { get; set; } = string.Empty;

    [JsonPropertyName("typ")]
    public string? Typ { get; set; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalMembers { get; set; }

    /// <summary>Emit the header as a canonical UTF-8 byte sequence and then base64url it for use in the JWS signing input.</summary>
    public string EncodeBase64Url()
    {
        var node = (JsonObject)JsonSerializer.SerializeToNode(this, HeaderContext.Header)!;
        // Drop the empty-string kid sentinel so headers built without a kid serialize without one.
        if (node.TryGetPropertyValue("kid", out var kidNode) && kidNode?.GetValue<string>() is "")
            node.Remove("kid");
        var bytes = DeterministicJsonWriter.WriteUtf8(node);
        return Base64Url.Encode(bytes);
    }

    /// <summary>Parse a base64url-encoded protected header back into a <see cref="JwsProtectedHeader"/>.</summary>
    /// <param name="encoded">Base64url string (no padding) carrying the JSON header.</param>
    /// <exception cref="MalformedJoseException">When <paramref name="encoded"/> is not valid base64url-encoded JSON.</exception>
    public static JwsProtectedHeader Decode(string encoded)
    {
        ArgumentException.ThrowIfNullOrEmpty(encoded);
        byte[] bytes;
        try
        {
            bytes = Base64Url.Decode(encoded);
        }
        catch (FormatException ex)
        {
            throw new MalformedJoseException("JWS protected header is not valid base64url.", ex);
        }

        try
        {
            return JsonSerializer.Deserialize<JwsProtectedHeader>(bytes, HeaderContext.Header)
                ?? throw new MalformedJoseException("JWS protected header decoded to null.");
        }
        catch (JsonException ex)
        {
            throw new MalformedJoseException("JWS protected header is not valid JSON.", ex);
        }
    }
}

/// <summary>Serializer options shared by the JWS/JWE header DTOs.</summary>
internal static class HeaderContext
{
    /// <summary>Alias of <see cref="JoseJson.Default"/> kept for call-site clarity.</summary>
    public static JsonSerializerOptions Header => JoseJson.Default;
}
