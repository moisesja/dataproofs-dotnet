using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Json;

namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// A minimal decode-and-verify view over a compact JWS used as an SD-JWT component (the
/// issuer-signed JWT and the Key Binding JWT). Exposes the decoded protected header and payload
/// as <see cref="JsonObject"/> for the SD-JWT processing rules, and verifies the signature
/// against a supplied public <see cref="Jwk"/> through the NetCrypto-backed
/// <see cref="IJoseCryptoProvider"/>. Internal: SD-JWT callers reuse the public
/// <see cref="Signing.JwsParser"/> guarantees indirectly through this shared decoder.
/// </summary>
internal sealed class CompactJwt
{
    private readonly string _signingInput;
    private readonly byte[] _signature;
    private readonly string _alg;

    private CompactJwt(JsonObject header, JsonObject payload, string signingInput, byte[] signature, string alg)
    {
        Header = header;
        Payload = payload;
        _signingInput = signingInput;
        _signature = signature;
        _alg = alg;
    }

    /// <summary>The decoded protected header.</summary>
    public JsonObject Header { get; }

    /// <summary>The decoded JWT payload (claims set).</summary>
    public JsonObject Payload { get; }

    /// <summary>The protected header <c>alg</c>.</summary>
    public string Algorithm => _alg;

    /// <summary>The protected header <c>typ</c>, if present.</summary>
    public string? Type => Header.TryGetPropertyValue("typ", out var t) && t is JsonValue tv && tv.GetValueKind() == JsonValueKind.String
        ? tv.GetValue<string>()
        : null;

    /// <summary>The protected header <c>kid</c>, if present.</summary>
    public string? KeyId => Header.TryGetPropertyValue("kid", out var k) && k is JsonValue kv && kv.GetValueKind() == JsonValueKind.String
        ? kv.GetValue<string>()
        : null;

    /// <summary>
    /// Decode a compact JWS into header/payload without verifying the signature. Use
    /// <see cref="Verify"/> afterward.
    /// </summary>
    /// <param name="compact">The compact JWS (three base64url segments).</param>
    /// <exception cref="MalformedJoseException">When the structure or JSON is invalid.</exception>
    public static CompactJwt Decode(string compact)
    {
        ArgumentException.ThrowIfNullOrEmpty(compact);
        var segments = compact.Split('.');
        if (segments.Length != 3)
            throw new MalformedJoseException($"Compact JWT must have exactly 3 dot-separated segments; got {segments.Length}.");
        if (segments[0].Length == 0 || segments[2].Length == 0)
            throw new MalformedJoseException("Compact JWT header or signature segment is empty.");

        var header = DecodeJsonObject(segments[0], "header");
        var payload = DecodeJsonObject(segments[1], "payload");

        // RFC 7515 §4.1.1: 'alg' is required; "none" is never accepted for a signed JWT (an
        // unsigned token must not be confusable with a signed one — RFC 9901 §10 / AC-3 negative).
        if (!header.TryGetPropertyValue("alg", out var algNode) || algNode is not JsonValue algValue
            || algValue.GetValueKind() != JsonValueKind.String)
            throw new MalformedJoseException("Compact JWT protected header is missing a string 'alg'.");
        var alg = algValue.GetValue<string>();
        if (string.IsNullOrEmpty(alg) || string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
            throw new MalformedJoseException("Compact JWT 'alg' is missing or \"none\"; unsigned JWT is not accepted.");

        // Reject a 'crit' header naming extensions we do not understand (RFC 7515 §4.1.11) — we
        // understand none. This keeps the SD-JWT issuer/KB JWTs aligned with the JwsParser policy.
        if (header.ContainsKey("crit"))
            throw new MalformedJoseException("Compact JWT marks an unsupported extension critical ('crit').");

        byte[] signature;
        try
        {
            signature = Base64Url.Decode(segments[2]);
        }
        catch (FormatException ex)
        {
            throw new MalformedJoseException("Compact JWT signature is not valid base64url.", ex);
        }

        var signingInput = segments[0] + "." + segments[1];
        return new CompactJwt(header, payload, signingInput, signature, alg);
    }

    /// <summary>
    /// Verify this JWT's signature against <paramref name="publicJwk"/>. The header <c>alg</c>
    /// must match the key's curve (algorithm-confusion defense).
    /// </summary>
    /// <param name="publicJwk">The verifier's public JWK.</param>
    /// <param name="cryptoProvider">The NetCrypto-backed crypto provider.</param>
    /// <returns><c>true</c> when the signature verifies; <c>false</c> otherwise.</returns>
    /// <exception cref="MalformedJoseException">When the JWK lacks a curve or is malformed.</exception>
    public bool Verify(Jwk publicJwk, IJoseCryptoProvider cryptoProvider)
    {
        ArgumentNullException.ThrowIfNull(publicJwk);
        ArgumentNullException.ThrowIfNull(cryptoProvider);

        if (string.IsNullOrEmpty(publicJwk.Crv))
            throw new MalformedJoseException("Verifier public JWK is missing 'crv'.");

        // alg ↔ key-curve binding: the header 'alg' must be the one this curve produces.
        if (!string.Equals(_alg, KeyTypeMapper.ToJwsAlgorithm(publicJwk.Crv), StringComparison.Ordinal))
            return false;

        var (_, publicKeyBytes) = JwkConversion.ExtractPublicKey(publicJwk);
        var data = Encoding.ASCII.GetBytes(_signingInput);
        try
        {
            return cryptoProvider.Verify(_alg, publicKeyBytes, data, _signature);
        }
        catch (NotSupportedException)
        {
            // Out-of-scope algorithm/curve (e.g. ES512) — treat as a verification failure, never
            // an unhandled throw (RFC 9901 §10 / AC-3 negative path).
            return false;
        }
    }

    private static JsonObject DecodeJsonObject(string segment, string what)
    {
        byte[] bytes;
        try
        {
            bytes = Base64Url.Decode(segment);
        }
        catch (FormatException ex)
        {
            throw new MalformedJoseException($"Compact JWT {what} is not valid base64url.", ex);
        }

        JsonNode? node;
        try
        {
            node = JsonNode.Parse(bytes, documentOptions: new JsonDocumentOptions { AllowDuplicateProperties = false });
        }
        catch (JsonException ex)
        {
            throw new MalformedJoseException($"Compact JWT {what} is not valid JSON.", ex);
        }

        if (node is not JsonObject obj)
            throw new MalformedJoseException($"Compact JWT {what} is not a JSON object.");
        return obj;
    }

    /// <summary>Serialize a claims object to the canonical JWT payload bytes for signing.</summary>
    public static byte[] SerializePayload(JsonObject payload)
        => Encoding.UTF8.GetBytes(payload.ToJsonString(JoseJson.Default));
}
