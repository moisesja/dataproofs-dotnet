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
        => DecodeCore(encoded, collectMemberNames: false).Header;

    /// <summary>
    /// Parse a protected header and retain its exact JSON member-name set. The raw set is needed
    /// when validating RFC 7515 protected/unprotected header disjointness: extension parameters
    /// are in the same namespace as modeled parameters such as <c>alg</c> and <c>kid</c>.
    /// </summary>
    public static (JwsProtectedHeader Header, IReadOnlySet<string> MemberNames) DecodeWithMemberNames(string encoded)
    {
        var (header, memberNames) = DecodeCore(encoded, collectMemberNames: true);
        return (header, memberNames!);
    }

    /// <summary>
    /// Shared decode path. <paramref name="collectMemberNames"/> is <c>false</c> for callers that
    /// only need the model (compact JWS, VC-JOSE): enumerating and hashing every member name is
    /// pure waste there, and the header is attacker-sized.
    /// </summary>
    private static (JwsProtectedHeader Header, IReadOnlySet<string>? MemberNames) DecodeCore(
        string encoded, bool collectMemberNames)
    {
        var bytes = DecodeBytes(encoded);

        try
        {
            using var document = JsonDocument.Parse(bytes, JoseJson.StrictDocument);

            // Establish the root really is an object before touching it by member. Every
            // JsonElement member accessor below (TryGetProperty, EnumerateObject) throws
            // InvalidOperationException — not JsonException — on a non-object root, and that would
            // escape this method's documented MalformedJoseException contract.
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new MalformedJoseException("JWS protected header is not a JSON object.");

            // RFC 7515 §4.1.4: the 'kid' value MUST be a case-sensitive string. A present-but-null
            // (or non-string) kid must be rejected here rather than deserialized into the model,
            // because JwsParser hands the kid straight to the caller's key resolver — outside its
            // try block — so a null would surface from the resolver as an undocumented
            // NullReferenceException/ArgumentNullException instead of MalformedJoseException. This
            // is the protected-header half of the check ReadUnprotectedKid already performs on the
            // unprotected header (issue #15).
            if (document.RootElement.TryGetProperty("kid", out var kid) && kid.ValueKind != JsonValueKind.String)
                throw new MalformedJoseException("JWS protected header 'kid' must be a string.");

            var header = document.RootElement.Deserialize<JwsProtectedHeader>(HeaderContext.Header)
                ?? throw new MalformedJoseException("JWS protected header decoded to null.");

            if (!collectMemberNames)
                return (header, null);

            var memberNames = document.RootElement.EnumerateObject()
                .Select(member => member.Name)
                .ToHashSet(StringComparer.Ordinal);
            return (header, memberNames);
        }
        catch (JsonException ex)
        {
            throw new MalformedJoseException("JWS protected header is not valid JSON.", ex);
        }
        catch (InvalidOperationException ex)
        {
            // JsonElement reports some structural and encoding faults as InvalidOperationException
            // rather than JsonException — notably a property name that is not valid UTF-8, which
            // only fails when transcoded to a string. Fail closed through the documented contract
            // so a caller's catch (MalformedJoseException) is never bypassed (issue #15).
            throw new MalformedJoseException("JWS protected header is malformed.", ex);
        }
    }

    private static byte[] DecodeBytes(string encoded)
    {
        if (string.IsNullOrEmpty(encoded))
            throw new MalformedJoseException("JWS protected header is empty.");
        try
        {
            return Base64Url.Decode(encoded);
        }
        catch (FormatException ex)
        {
            throw new MalformedJoseException("JWS protected header is not valid base64url.", ex);
        }
    }
}

/// <summary>Serializer options shared by the JWS/JWE header DTOs.</summary>
internal static class HeaderContext
{
    /// <summary>Alias of <see cref="JoseJson.Default"/> kept for call-site clarity.</summary>
    public static JsonSerializerOptions Header => JoseJson.Default;
}
