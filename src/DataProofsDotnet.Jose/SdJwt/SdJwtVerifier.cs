using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// Verifies SD-JWT presentations (RFC 9901 §7): verifies the Issuer JWT signature, reconstructs
/// the processed (disclosed) payload by resolving every <c>_sd</c> digest and array-element
/// <c>{"...": digest}</c> placeholder against the presented Disclosures (rejecting
/// undisclosed/duplicate/unknown/shape-mismatched digests), and — when a Key Binding JWT is
/// present or required — verifies it (<c>typ</c>, signature under the SD-JWT's <c>cnf</c> key,
/// <c>sd_hash</c>, <c>aud</c>, <c>nonce</c>, freshness). Returns a structured
/// <see cref="SdJwtVerificationResult"/>; a structurally valid but failing presentation yields
/// <see cref="SdJwtVerificationResult.IsValid"/> <c>false</c> rather than throwing
/// (PRD FR-3/FR-23). Stateless and thread-safe.
/// </summary>
public static class SdJwtVerifier
{
    /// <summary>
    /// Verify a presented SD-JWT (with or without a Key Binding JWT) against the Issuer's public
    /// key. The Issuer JWT signature is checked first; on success the disclosed payload is
    /// reconstructed and (when applicable) the KB-JWT is verified.
    /// </summary>
    /// <param name="presentation">The presented SD-JWT (<c>issuer-JWT~D1~…~Dn~</c> optionally followed by a KB-JWT).</param>
    /// <param name="resolveIssuerPublicJwk">
    /// Maps the Issuer JWT's <c>kid</c> (empty string when the header carries none) to the
    /// Issuer's public JWK; returns <c>null</c> when the kid is unknown.
    /// </param>
    /// <param name="options">Verification/Key-Binding policy; <c>null</c> uses the defaults.</param>
    /// <param name="cryptoProvider">The crypto provider; <c>null</c> uses a fresh <see cref="JoseCryptoProvider"/>.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="presentation"/> or <paramref name="resolveIssuerPublicJwk"/> is null.</exception>
    public static SdJwtVerificationResult Verify(
        string presentation,
        Func<string, Jwk?> resolveIssuerPublicJwk,
        SdJwtVerificationOptions? options = null,
        IJoseCryptoProvider? cryptoProvider = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(presentation);
        ArgumentNullException.ThrowIfNull(resolveIssuerPublicJwk);
        options ??= new SdJwtVerificationOptions();
        cryptoProvider ??= new JoseCryptoProvider();

        // 1. Structural decomposition. A first element that is not a compact JWT, or a malformed
        //    Disclosure, is a structural failure we surface as a result (never an unhandled throw).
        SdJwtComponents components;
        CompactJwt issuerJwt;
        try
        {
            components = SdJwtComponents.Parse(presentation);
            issuerJwt = CompactJwt.Decode(components.IssuerJwt);
        }
        catch (MalformedJoseException ex)
        {
            return SdJwtVerificationResult.Failure($"MALFORMED: {ex.Message}");
        }

        // 2. Resolve _sd_alg up front so an unsupported algorithm fails before any digesting,
        //    closing the RFC 9901 §10 hash-downgrade vector.
        string sdAlg;
        try
        {
            sdAlg = SdJwtClaims.ResolveSdAlg(issuerJwt.Payload);
        }
        catch (MalformedJoseException ex)
        {
            return SdJwtVerificationResult.Failure($"MALFORMED: {ex.Message}", issuerJwt.Algorithm);
        }

        // 3. Verify the Issuer JWT signature. The kid → JWK resolver mirrors the JwsParser/JwtHandler
        //    contract; an unknown kid or a non-verifying signature is a hard failure.
        var issuerKid = issuerJwt.KeyId ?? string.Empty;
        var issuerPublicJwk = resolveIssuerPublicJwk(issuerKid);
        if (issuerPublicJwk is null)
            return SdJwtVerificationResult.Failure(
                $"ISSUER_KEY_UNRESOLVED: no Issuer public JWK supplied for kid '{issuerKid}'.", issuerJwt.Algorithm);

        bool issuerSignatureVerified;
        try
        {
            issuerSignatureVerified = issuerJwt.Verify(issuerPublicJwk, cryptoProvider);
        }
        catch (MalformedJoseException ex)
        {
            return SdJwtVerificationResult.Failure($"ISSUER_KEY_INVALID: {ex.Message}", issuerJwt.Algorithm);
        }
        if (!issuerSignatureVerified)
            return SdJwtVerificationResult.Failure(
                "ISSUER_SIGNATURE_INVALID: the SD-JWT Issuer JWT signature did not verify.", issuerJwt.Algorithm);

        // 4. Reconstruct the disclosed payload (RFC 9901 §7.1): resolve every digest against the
        //    presented Disclosures, rejecting unknown/duplicate/shape-mismatched/unused ones.
        JsonObject disclosedPayload;
        try
        {
            disclosedPayload = SdJwtReconstructor.Reconstruct(issuerJwt.Payload, components.Disclosures, sdAlg);
        }
        catch (MalformedJoseException ex)
        {
            return SdJwtVerificationResult.Failure($"DISCLOSURE_INVALID: {ex.Message}", issuerJwt.Algorithm);
        }

        // 5. Key Binding (RFC 9901 §7.3).
        var keyBindingVerified = false;
        if (components.HasKeyBinding)
        {
            var cnf = SafeGetConfirmationKey(issuerJwt.Payload, out var cnfError);
            if (cnfError is not null)
                return SdJwtVerificationResult.Failure($"DISCLOSURE_INVALID: {cnfError}", issuerJwt.Algorithm);
            if (cnf is null)
                return SdJwtVerificationResult.Failure(
                    "KB_JWT_NO_CNF: the presentation carries a Key Binding JWT but the SD-JWT has no 'cnf' key to verify it against (RFC 9901 §7.3).",
                    issuerJwt.Algorithm);

            var kbErrors = KeyBindingJwt.Verify(
                components.KeyBindingJwt!, components.SdJwtWithoutKeyBinding, sdAlg, cnf, options, cryptoProvider);
            if (kbErrors.Count > 0)
                return SdJwtVerificationResult.Failure(kbErrors, issuerJwt.Algorithm);
            keyBindingVerified = true;
        }
        else if (options.RequireKeyBinding)
        {
            return SdJwtVerificationResult.Failure(
                "KB_JWT_REQUIRED: the verification policy requires a Key Binding JWT, but the presentation carries none.",
                issuerJwt.Algorithm);
        }

        return SdJwtVerificationResult.Success(disclosedPayload, keyBindingVerified, issuerJwt.Algorithm);
    }

    private static Jwk? SafeGetConfirmationKey(JsonObject payload, out string? error)
    {
        try
        {
            error = null;
            return SdJwtClaims.TryGetConfirmationKey(payload);
        }
        catch (MalformedJoseException ex)
        {
            error = ex.Message;
            return null;
        }
    }
}
