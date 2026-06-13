using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Signing;

namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// Key Binding JWT (RFC 9901 §7.3): a Holder-signed JWT, typ <c>kb+jwt</c>, that binds an
/// SD-JWT presentation to an audience and nonce via the <c>sd_hash</c> claim
/// (<c>base64url(hash(ASCII(SD-JWT-up-to-and-including-final-tilde)))</c>). Stateless; the
/// signing entry point is async over a NetCrypto <see cref="JwsSigner"/> (NFR-3, AC-8).
/// </summary>
public static class KeyBindingJwt
{
    /// <summary>The required KB-JWT <c>typ</c> protected-header value (RFC 9901 §7.3).</summary>
    public const string Type = "kb+jwt";

    /// <summary>
    /// Issue a Key Binding JWT over a presented SD-JWT. The <c>sd_hash</c> is computed from
    /// <paramref name="sdJwtWithoutKeyBinding"/> under <paramref name="sdAlg"/>; the JWT carries
    /// <c>nonce</c>, <c>aud</c>, <c>iat</c>, and <c>sd_hash</c>.
    /// </summary>
    /// <param name="sdJwtWithoutKeyBinding">The presented SD-JWT up to and including the final <c>~</c> (no KB-JWT).</param>
    /// <param name="sdAlg">The SD-JWT <c>_sd_alg</c> hash algorithm name.</param>
    /// <param name="nonce">The Verifier-provided nonce to echo (replay defense).</param>
    /// <param name="audience">The intended audience (the Verifier's identifier).</param>
    /// <param name="issuedAt">The KB-JWT <c>iat</c>.</param>
    /// <param name="holderSigner">The Holder's NetCrypto-backed signer.</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    public static async Task<string> IssueAsync(
        string sdJwtWithoutKeyBinding,
        string sdAlg,
        string nonce,
        string audience,
        DateTimeOffset issuedAt,
        JwsSigner holderSigner,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sdJwtWithoutKeyBinding);
        ArgumentException.ThrowIfNullOrEmpty(nonce);
        ArgumentException.ThrowIfNullOrEmpty(audience);
        ArgumentNullException.ThrowIfNull(holderSigner);

        var sdHash = SdHashAlgorithm.ComputeSdHash(sdAlg, sdJwtWithoutKeyBinding);

        // RFC 9901 §7.3 KB-JWT payload, in spec order.
        var payload = new JsonObject
        {
            ["nonce"] = nonce,
            ["aud"] = audience,
            ["iat"] = issuedAt.ToUnixTimeSeconds(),
            ["sd_hash"] = sdHash,
        };
        var payloadBytes = Encoding.UTF8.GetBytes(payload.ToJsonString(Json.JoseJson.Default));

        // typ MUST be "kb+jwt"; this is the only place the KB-JWT typ is set.
        return await JwsBuilder.BuildCompactAsync(payloadBytes, holderSigner, typ: Type, detachedPayload: false, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Verify a Key Binding JWT against the presented SD-JWT (RFC 9901 §7.3): the header
    /// <c>typ</c> MUST be <c>kb+jwt</c>; the signature MUST verify under the SD-JWT's <c>cnf</c>
    /// Holder key; the <c>sd_hash</c> claim MUST equal the recomputed hash over
    /// <paramref name="sdJwtWithoutKeyBinding"/>; and <c>aud</c>/<c>nonce</c> (and, when set, the
    /// <c>iat</c> freshness bound) MUST match the Verifier's expectations. Returns the collected
    /// failure reasons (empty when the KB-JWT is valid). Never throws on a bad KB-JWT — structural
    /// issues are reported as failures.
    /// </summary>
    /// <param name="keyBindingJwtCompact">The KB-JWT compact serialization (the presentation's final element).</param>
    /// <param name="sdJwtWithoutKeyBinding">The presented SD-JWT up to and including the final <c>~</c>.</param>
    /// <param name="sdAlg">The SD-JWT <c>_sd_alg</c> hash algorithm name (also names the <c>sd_hash</c> hash).</param>
    /// <param name="holderConfirmationKey">The Holder confirmation key from the SD-JWT's <c>cnf</c>/<c>jwk</c>.</param>
    /// <param name="options">Verifier policy (expected audience/nonce, freshness bound, clock skew).</param>
    /// <param name="cryptoProvider">The NetCrypto-backed crypto provider.</param>
    internal static IReadOnlyList<string> Verify(
        string keyBindingJwtCompact,
        string sdJwtWithoutKeyBinding,
        string sdAlg,
        Jwk holderConfirmationKey,
        SdJwtVerificationOptions options,
        IJoseCryptoProvider cryptoProvider)
    {
        var errors = new List<string>();

        CompactJwt kbJwt;
        try
        {
            kbJwt = CompactJwt.Decode(keyBindingJwtCompact);
        }
        catch (MalformedJoseException ex)
        {
            errors.Add($"KB_JWT_MALFORMED: {ex.Message}");
            return errors;
        }

        // RFC 9901 §7.3: the KB-JWT typ header MUST be "kb+jwt". Pinning it prevents a plain JWT
        // (or an SD-JWT-issuer JWT) being replayed as a KB-JWT (token-confusion defense).
        if (!string.Equals(kbJwt.Type, Type, StringComparison.Ordinal))
            errors.Add($"KB_JWT_TYP_INVALID: Key Binding JWT 'typ' must be \"{Type}\"; found \"{kbJwt.Type ?? "(absent)"}\".");

        // Signature under the cnf Holder key (proof of possession).
        bool signatureVerified;
        try
        {
            signatureVerified = kbJwt.Verify(holderConfirmationKey, cryptoProvider);
        }
        catch (MalformedJoseException ex)
        {
            errors.Add($"KB_JWT_CNF_INVALID: {ex.Message}");
            return errors;
        }
        if (!signatureVerified)
            errors.Add("KB_JWT_SIGNATURE_INVALID: Key Binding JWT signature did not verify under the SD-JWT 'cnf' key.");

        // sd_hash: recompute over the presented SD-JWT (RFC 9901 §7.3) and compare in constant
        // time (NFR-6). A mismatch means the KB-JWT was minted over a different presentation.
        var presentedSdHash = SdHashAlgorithm.ComputeSdHash(sdAlg, sdJwtWithoutKeyBinding);
        var claimedSdHash = GetStringClaim(kbJwt.Payload, "sd_hash");
        if (claimedSdHash is null)
            errors.Add("KB_JWT_SD_HASH_MISSING: Key Binding JWT has no string 'sd_hash' claim (RFC 9901 §7.3).");
        else if (!FixedTimeEquals(presentedSdHash, claimedSdHash))
            errors.Add("KB_JWT_SD_HASH_MISMATCH: Key Binding JWT 'sd_hash' does not match the presented SD-JWT (RFC 9901 §7.3).");

        // aud: the Verifier MUST be the intended audience.
        var aud = GetStringClaim(kbJwt.Payload, "aud");
        if (options.ExpectedAudience is null)
            errors.Add("KB_JWT_AUDIENCE_UNCHECKED: a Key Binding JWT is present but no ExpectedAudience was supplied to verify 'aud' (RFC 9901 §7.3).");
        else if (!string.Equals(aud, options.ExpectedAudience, StringComparison.Ordinal))
            errors.Add($"KB_JWT_AUDIENCE_MISMATCH: Key Binding JWT 'aud' is '{aud ?? "(absent)"}', expected '{options.ExpectedAudience}'.");

        // nonce: replay/freshness binding to the Verifier's challenge.
        var nonce = GetStringClaim(kbJwt.Payload, "nonce");
        if (options.ExpectedNonce is null)
            errors.Add("KB_JWT_NONCE_UNCHECKED: a Key Binding JWT is present but no ExpectedNonce was supplied to verify 'nonce' (RFC 9901 §7.3 / §10).");
        else if (!string.Equals(nonce, options.ExpectedNonce, StringComparison.Ordinal))
            errors.Add("KB_JWT_NONCE_MISMATCH: Key Binding JWT 'nonce' does not match the expected value (replay defense, RFC 9901 §10).");

        // iat freshness bound (optional). RFC 9901 §10 RECOMMENDS the Verifier bound the KB-JWT age.
        if (options.MaxKeyBindingAge is { } maxAge)
        {
            var iat = GetNumericDateClaim(kbJwt.Payload, "iat");
            if (iat is null)
            {
                errors.Add("KB_JWT_IAT_MISSING: a MaxKeyBindingAge bound was set but the Key Binding JWT has no numeric 'iat' claim.");
            }
            else
            {
                var now = options.CurrentTime ?? DateTimeOffset.UtcNow;
                if (now - iat.Value > maxAge + options.ClockSkew)
                    errors.Add($"KB_JWT_EXPIRED: Key Binding JWT 'iat' is older than the {maxAge} freshness bound (replay defense, RFC 9901 §10).");
                if (iat.Value - now > options.ClockSkew)
                    errors.Add("KB_JWT_IAT_IN_FUTURE: Key Binding JWT 'iat' is in the future beyond the allowed clock skew.");
            }
        }

        return errors;
    }

    private static bool FixedTimeEquals(string a, string b)
        => CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(a), Encoding.ASCII.GetBytes(b));

    private static string? GetStringClaim(JsonObject payload, string name)
        => payload.TryGetPropertyValue(name, out var node) && node is JsonValue v && v.GetValueKind() == JsonValueKind.String
            ? v.GetValue<string>()
            : null;

    private static DateTimeOffset? GetNumericDateClaim(JsonObject payload, string name)
    {
        if (!payload.TryGetPropertyValue(name, out var node) || node is not JsonValue v)
            return null;
        if (v.TryGetValue<long>(out var seconds))
            return DateTimeOffset.FromUnixTimeSeconds(seconds);
        if (v.TryGetValue<double>(out var fractional) && !double.IsNaN(fractional) && !double.IsInfinity(fractional))
            return DateTimeOffset.FromUnixTimeSeconds((long)fractional);
        return null;
    }
}
