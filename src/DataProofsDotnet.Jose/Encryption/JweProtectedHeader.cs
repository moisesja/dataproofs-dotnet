using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using DataProofsDotnet.Jose.Json;

namespace DataProofsDotnet.Jose.Encryption;

/// <summary>
/// DTO for the JWE protected header. The ECDH-ES path uses
/// <c>{ typ?, alg, enc, epk, apv? }</c>; ECDH-1PU adds <c>{ apu, skid }</c>; the standalone
/// <c>A256KW</c> path uses <c>{ typ?, alg, enc, kid? }</c>. One DTO so JWE construction and
/// parsing share a single shape. Ported from didcomm-dotnet
/// <c>DidComm.Jose.Encryption.JweProtectedHeader</c> (PRD §1.4 item 2); <c>apv</c> made
/// optional and <c>kid</c> added for the generic-JOSE (non-DIDComm-profile) and compact paths.
/// </summary>
internal sealed class JweProtectedHeader
{
    [JsonPropertyName("typ")]
    public string? Typ { get; set; }

    [JsonPropertyName("alg")]
    public string Alg { get; set; } = string.Empty;

    [JsonPropertyName("enc")]
    public string Enc { get; set; } = string.Empty;

    [JsonPropertyName("epk")]
    public Jwk? Epk { get; set; }

    [JsonPropertyName("apv")]
    public string? Apv { get; set; }

    [JsonPropertyName("apu")]
    public string? Apu { get; set; }

    [JsonPropertyName("skid")]
    public string? Skid { get; set; }

    [JsonPropertyName("kid")]
    public string? Kid { get; set; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalMembers { get; set; }

    /// <summary>Canonical base64url encoding used for the JWE AAD input.</summary>
    public string EncodeBase64Url()
    {
        var node = (JsonObject)JsonSerializer.SerializeToNode(this, JoseJson.JweHeaderTypeInfo)!;
        var bytes = DeterministicJsonWriter.WriteUtf8(node);
        return Base64Url.Encode(bytes);
    }

    /// <summary>Inverse of <see cref="EncodeBase64Url"/>; used by the parser on receive.</summary>
    /// <param name="encoded">Base64url-encoded JSON header.</param>
    /// <exception cref="MalformedJoseException">
    /// When <paramref name="encoded"/> is empty or not valid base64url, does not decode to valid
    /// UTF-8 (RFC 7516 §5.2 step 3), contains an unpaired-surrogate escape, or is not valid JSON.
    /// </exception>
    public static JweProtectedHeader Decode(string encoded)
    {
        // The value comes straight from the envelope ("protected": ""), so an empty one is malformed
        // input, not caller misuse: ArgumentException would escape JweParser's documented contract
        // before any key work. Mirrors JwsProtectedHeader (issue #30).
        if (string.IsNullOrEmpty(encoded))
            throw new MalformedJoseException("JWE protected header is empty.");
        byte[] bytes;
        try
        {
            bytes = Base64Url.Decode(encoded);
        }
        catch (FormatException ex)
        {
            throw new MalformedJoseException("JWE protected header is not valid base64url.", ex);
        }

        // RFC 7516 §5.2 step 3: the decoded octets MUST be UTF-8. The deserializer below does not
        // check: an unknown member name reaches the extension bag through a lossy decode and an
        // extension string value — invalid octets or an unpaired-surrogate escape — is never
        // transcoded at all (issues #28, #30).
        JoseJson.RequireTranscodableJson(bytes, "JWE protected header");

        try
        {
            return JsonSerializer.Deserialize(bytes, JoseJson.JweHeaderTypeInfo)
                ?? throw new MalformedJoseException("JWE protected header decoded to null.");
        }
        catch (JsonException ex)
        {
            throw new MalformedJoseException("JWE protected header is not valid JSON.", ex);
        }
    }
}
