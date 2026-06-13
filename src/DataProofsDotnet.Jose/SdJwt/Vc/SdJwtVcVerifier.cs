using System.Text.Json;
using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// Verifies SD-JWT VC presentations (draft-ietf-oauth-sd-jwt-vc-16 §3.5): runs the generic
/// SD-JWT verification (FR-16) and then enforces the profile rules — the issuer-JWT media type
/// (<c>dc+sd-jwt</c>, with the transitional <c>vc+sd-jwt</c> accepted on input), the REQUIRED
/// <c>vct</c> claim, and the rule that no registered must-not-disclose claim was selectively
/// disclosed. When an <see cref="ITypeMetadataResolver"/> is supplied, the <c>vct</c> Type
/// Metadata is retrieved through it (offline/local-cache by default — never the network unless
/// the consumer's resolver opts in, FR-17). Returns a structured result; never throws on a
/// structurally valid but failing presentation (PRD FR-3/FR-23). Stateless and thread-safe.
/// </summary>
public static class SdJwtVcVerifier
{
    /// <summary>
    /// Verify a presented SD-JWT VC against the Issuer's public key and the profile rules,
    /// optionally retrieving Type Metadata for the <c>vct</c>.
    /// </summary>
    /// <param name="presentation">The presented SD-JWT VC (issuer JWT, disclosures, optional KB-JWT).</param>
    /// <param name="resolveIssuerPublicJwk">Maps the issuer-JWT <c>kid</c> (empty when absent) to the Issuer's public JWK.</param>
    /// <param name="options">SD-JWT verification/Key-Binding policy; <c>null</c> uses the defaults.</param>
    /// <param name="typeMetadataResolver">
    /// Optional <c>vct</c> Type Metadata resolver; <c>null</c> skips metadata retrieval. Default
    /// implementations are offline (<see cref="LocalCacheTypeMetadataResolver"/>).
    /// </param>
    /// <param name="cryptoProvider">The crypto provider; <c>null</c> uses a fresh <see cref="JoseCryptoProvider"/>.</param>
    /// <param name="cancellationToken">Cancels any Type Metadata retrieval the resolver performs.</param>
    public static async Task<SdJwtVcVerificationResult> VerifyAsync(
        string presentation,
        Func<string, Jwk?> resolveIssuerPublicJwk,
        SdJwtVerificationOptions? options = null,
        ITypeMetadataResolver? typeMetadataResolver = null,
        IJoseCryptoProvider? cryptoProvider = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(presentation);
        ArgumentNullException.ThrowIfNull(resolveIssuerPublicJwk);

        // 1. Media-type gate (§3.5): the issuer-JWT typ must be dc+sd-jwt, or the transitional
        //    vc+sd-jwt accepted on input only. This runs before the cryptographic verification so a
        //    non-VC SD-JWT is rejected with a profile-specific failure.
        SdJwtComponents components;
        CompactJwt issuerJwt;
        try
        {
            components = SdJwtComponents.Parse(presentation);
            issuerJwt = CompactJwt.Decode(components.IssuerJwt);
        }
        catch (MalformedJoseException ex)
        {
            return SdJwtVcVerificationResult.Failure($"MALFORMED: {ex.Message}");
        }

        var typ = issuerJwt.Type;
        if (typ is not (SdJwtVcConstants.MediaType or SdJwtVcConstants.TransitionalMediaType))
        {
            return SdJwtVcVerificationResult.Failure(
                $"VC_MEDIA_TYPE_INVALID: SD-JWT VC issuer-JWT 'typ' must be '{SdJwtVcConstants.MediaType}' " +
                $"(or transitional '{SdJwtVcConstants.TransitionalMediaType}'); found '{typ ?? "(absent)"}' (draft-ietf-oauth-sd-jwt-vc-16 §3.5).");
        }

        // 2. Generic SD-JWT verification (signature, reconstruction, KB-JWT).
        var inner = SdJwtVerifier.Verify(presentation, resolveIssuerPublicJwk, options, cryptoProvider);
        if (!inner.IsValid || inner.DisclosedPayload is not { } disclosed)
            return SdJwtVcVerificationResult.Failure(inner.Errors.Count > 0 ? inner.Errors : ["VERIFICATION_FAILED"]);

        // 3. No registered must-not-disclose claim may have been selectively disclosed (§3.2.2.2):
        //    if any presented Disclosure names one, the profile is violated.
        foreach (var disclosure in components.Disclosures)
        {
            if (disclosure.ClaimName is { } name && SdJwtVcConstants.MustNotBeSelectivelyDisclosed.Contains(name, StringComparer.Ordinal))
            {
                return SdJwtVcVerificationResult.Failure(
                    $"VC_DISALLOWED_DISCLOSURE: SD-JWT VC claim '{name}' MUST NOT be selectively disclosed (draft-ietf-oauth-sd-jwt-vc-16 §3.2.2.2).");
            }
        }

        // 4. vct REQUIRED, a non-empty string, present in the (cleared) disclosed payload (§3.2.2.1.1).
        if (!disclosed.TryGetPropertyValue(SdJwtVcConstants.VctClaim, out var vctNode)
            || vctNode is not JsonValue vctValue
            || vctValue.GetValueKind() != JsonValueKind.String
            || string.IsNullOrEmpty(vctValue.GetValue<string>()))
        {
            return SdJwtVcVerificationResult.Failure(
                "VC_VCT_MISSING: SD-JWT VC payload has no non-empty string 'vct' claim (draft-ietf-oauth-sd-jwt-vc-16 §3.2.2.1.1).");
        }
        var vct = vctValue.GetValue<string>();

        // 5. Optional Type Metadata retrieval — offline by default, never network unless the
        //    consumer's resolver opts in (FR-17 posture).
        JsonObject? typeMetadata = null;
        if (typeMetadataResolver is not null)
        {
            typeMetadata = await typeMetadataResolver.ResolveAsync(vct, cancellationToken).ConfigureAwait(false);
        }

        return SdJwtVcVerificationResult.Success(disclosed, vct, typeMetadata, inner.KeyBindingVerified);
    }
}
