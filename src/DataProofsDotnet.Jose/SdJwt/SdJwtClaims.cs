using System.Text.Json;
using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// Reads the SD-JWT control claims (<c>_sd_alg</c>, <c>cnf</c>) from an issuer-JWT payload
/// (RFC 9901 §4.1.1 / §6). Internal helper shared by the holder and verifier.
/// </summary>
internal static class SdJwtClaims
{
    /// <summary>
    /// Resolve the <c>_sd_alg</c> value, defaulting to <c>sha-256</c> when absent (RFC 9901
    /// §4.1.1), and reject an unsupported algorithm.
    /// </summary>
    /// <exception cref="MalformedJoseException">When <c>_sd_alg</c> is present but not a supported SHA-2 name.</exception>
    public static string ResolveSdAlg(JsonObject payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (!payload.TryGetPropertyValue("_sd_alg", out var node) || node is null)
            return SdHashAlgorithm.Default;

        if (node is not JsonValue v || v.GetValueKind() != JsonValueKind.String)
            throw new MalformedJoseException("SD-JWT '_sd_alg' must be a string (RFC 9901 §4.1.1).");

        var sdAlg = v.GetValue<string>();
        if (!SdHashAlgorithm.IsSupported(sdAlg))
            throw new MalformedJoseException(
                $"Unsupported SD-JWT '_sd_alg' value '{sdAlg}'. Supported: sha-256, sha-384, sha-512 (RFC 9901 §4.1.1).");
        return sdAlg;
    }

    /// <summary>
    /// Extract the Holder confirmation key from the <c>cnf</c>/<c>jwk</c> claim, or <c>null</c>
    /// when no <c>cnf</c> is present.
    /// </summary>
    /// <exception cref="MalformedJoseException">When <c>cnf</c> is present but not a <c>jwk</c> object.</exception>
    public static Jwk? TryGetConfirmationKey(JsonObject payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (!payload.TryGetPropertyValue("cnf", out var cnfNode) || cnfNode is null)
            return null;

        if (cnfNode is not JsonObject cnf)
            throw new MalformedJoseException("SD-JWT 'cnf' must be a JSON object (RFC 7800).");
        if (!cnf.TryGetPropertyValue("jwk", out var jwkNode) || jwkNode is null)
            throw new MalformedJoseException("SD-JWT 'cnf' does not carry a 'jwk' member; only the cnf/jwk Key Binding method is supported.");
        if (jwkNode is not JsonObject)
            throw new MalformedJoseException("SD-JWT 'cnf'/'jwk' must be a JSON object.");

        try
        {
            return JsonSerializer.Deserialize<Jwk>(jwkNode.ToJsonString(), Json.JoseJson.Default)
                ?? throw new MalformedJoseException("SD-JWT 'cnf'/'jwk' deserialized to null.");
        }
        catch (JsonException ex)
        {
            throw new MalformedJoseException("SD-JWT 'cnf'/'jwk' is not a valid JWK.", ex);
        }
    }
}
