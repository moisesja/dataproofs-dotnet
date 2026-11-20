using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// Verifies SD-JWT VC presentations (draft-ietf-oauth-sd-jwt-vc-27 §2.4): runs the generic
/// SD-JWT verification (FR-16) and then enforces the profile rules — the issuer-JWT <c>typ</c> is
/// exactly <c>dc+sd-jwt</c> (§2.2.1; the former <c>vc+sd-jwt</c> is rejected), the REQUIRED
/// <c>vct</c> claim (§2.2.2.1), a well-formed <c>aka_vcts</c> claim when present (§2.2.2.2), and
/// the rule that no registered must-not-disclose claim was selectively disclosed (§2.2.2.3). When
/// an <see cref="ITypeMetadataResolver"/> is supplied, the <c>vct</c> Type Metadata is retrieved
/// through it (offline/local-cache by default — never the network unless the consumer's resolver
/// opts in, FR-17). Returns a structured result; never throws on a structurally valid but failing
/// presentation (PRD FR-3/FR-23). Stateless and thread-safe.
/// </summary>
/// <remarks>
/// Not done here, and left to the caller: processing the retrieved Type Metadata (§5.7), checking
/// <c>status</c> (§2.4 says a Verifier SHOULD), and the Issuer key discovery and validation policy of
/// §2.5, which the <c>resolveIssuerPublicJwk</c> callback stands for.
/// </remarks>
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

        // 1. Media-type gate (§2.2.1): the issuer-JWT typ must be exactly dc+sd-jwt. The transitional
        //    vc+sd-jwt that drafts up to -18 accepted is refused (-19 removed it; W3C VC-JOSE-COSE uses
        //    that name for a different format). This runs before the cryptographic verification so a
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
        if (!string.Equals(typ, SdJwtVcConstants.MediaType, StringComparison.Ordinal))
        {
            return SdJwtVcVerificationResult.Failure(
                $"VC_MEDIA_TYPE_INVALID: SD-JWT VC issuer-JWT 'typ' must be '{SdJwtVcConstants.MediaType}'; " +
                $"found '{typ ?? "(absent)"}' ({SdJwtVcConstants.Revision} §2.2.1).");
        }

        // 2. Generic SD-JWT verification (signature, reconstruction, KB-JWT).
        var inner = SdJwtVerifier.Verify(presentation, resolveIssuerPublicJwk, options, cryptoProvider);
        if (!inner.IsValid || inner.DisclosedPayload is not { } disclosed)
            return SdJwtVcVerificationResult.Failure(inner.Errors.Count > 0 ? inner.Errors : ["VERIFICATION_FAILED"]);

        // 3. No registered must-not-disclose claim may have been selectively disclosed (§2.2.2.3):
        //    if any presented Disclosure names one, the profile is violated.
        foreach (var disclosure in components.Disclosures)
        {
            if (disclosure.ClaimName is { } name && SdJwtVcConstants.MustNotBeSelectivelyDisclosed.Contains(name, StringComparer.Ordinal))
            {
                return SdJwtVcVerificationResult.Failure(
                    $"VC_DISALLOWED_DISCLOSURE: SD-JWT VC claim '{name}' MUST NOT be selectively disclosed ({SdJwtVcConstants.Revision} §2.2.2.3).");
            }
        }

        // 4. vct REQUIRED, a non-empty string, present in the (cleared) disclosed payload (§2.2.2.1).
        if (!disclosed.TryGetPropertyValue(SdJwtVcConstants.VctClaim, out var vctNode)
            || SdJwtVcClaimRules.ReadTypeValue(vctNode) is not { } vct)
        {
            return SdJwtVcVerificationResult.Failure(
                $"VC_VCT_MISSING: SD-JWT VC payload has no non-empty string 'vct' claim ({SdJwtVcConstants.Revision} §2.2.2.1).");
        }

        // 5. aka_vcts OPTIONAL; when present, a non-empty array of strings without the vct value (§2.2.2.2).
        //    Step 3 refuses a Disclosure that names aka_vcts; it does not yet see one that hides an element
        //    of the array, which the sub-claim rule of §2.2.2.3 also forbids.
        if (SdJwtVcClaimRules.AkaVctsViolation(disclosed, vct) is { } akaVctsViolation)
        {
            return SdJwtVcVerificationResult.Failure(
                $"VC_AKA_VCTS_INVALID: SD-JWT VC claim 'aka_vcts' {akaVctsViolation} ({SdJwtVcConstants.Revision} §2.2.2.2).");
        }

        // 6. Optional Type Metadata retrieval (§5.3) — offline by default, never network unless the
        //    consumer's resolver opts in (FR-17 posture).
        JsonObject? typeMetadata = null;
        if (typeMetadataResolver is not null)
        {
            typeMetadata = await typeMetadataResolver.ResolveAsync(vct, cancellationToken).ConfigureAwait(false);
        }

        return SdJwtVcVerificationResult.Success(disclosed, vct, typeMetadata, inner.KeyBindingVerified);
    }
}
