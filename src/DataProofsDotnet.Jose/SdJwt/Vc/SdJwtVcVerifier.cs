using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// Verifies SD-JWT VC presentations (draft-ietf-oauth-sd-jwt-vc-27 §2.4): runs the generic
/// SD-JWT verification (FR-16) and then enforces the profile rules — the issuer-JWT <c>typ</c> is
/// exactly <c>dc+sd-jwt</c> (§2.2.1; the former <c>vc+sd-jwt</c> is rejected), the REQUIRED
/// <c>vct</c> claim (§2.2.2.1), a well-formed <c>aka_vcts</c> claim when present (§2.2.2.2), and
/// the rule that no registered must-not-disclose claim, nor anything inside one, was selectively
/// disclosed (§2.2.2.3; a nested claim that only shares a reserved name is not affected). When
/// an <see cref="ITypeMetadataResolver"/> is supplied, the <c>vct</c> Type Metadata is retrieved
/// through it (offline/local-cache by default — never the network unless the consumer's resolver
/// opts in, FR-17) and returned unprocessed; <see cref="VerifyWithTypeMetadataAsync"/> processes it
/// fully (§5.7) and rejects a credential that contradicts it. Returns a structured result; never throws
/// on a structurally valid but failing presentation (PRD FR-3/FR-23). Stateless and thread-safe.
/// </summary>
/// <remarks>
/// Not done here, and left to the caller: checking <c>status</c> (§2.4 says a Verifier SHOULD), and the
/// Issuer key discovery and validation policy of §2.5, which the <c>resolveIssuerPublicJwk</c> callback
/// stands for. Nor does Type Metadata establish trust or authorization (§7.7, §7.8): a type that extends a
/// known type gives its issuer no authority to issue it.
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

        var verified = VerifyProfile(presentation, resolveIssuerPublicJwk, options, cryptoProvider);
        if (verified.Failure is { } failure)
            return failure;

        // 6. Optional Type Metadata retrieval (§5.3) — offline by default, never network unless the
        //    consumer's resolver opts in (FR-17 posture). The document is returned as retrieved, unprocessed.
        JsonObject? typeMetadata = null;
        if (typeMetadataResolver is not null)
        {
            typeMetadata = await typeMetadataResolver.ResolveAsync(verified.Vct!, cancellationToken).ConfigureAwait(false);
        }

        return SdJwtVcVerificationResult.Success(verified.Disclosed!, verified.Vct!, typeMetadata, verified.KeyBindingVerified);
    }

    /// <summary>
    /// Verify a presented SD-JWT VC as <see cref="VerifyAsync"/> does, then fully process its Type Metadata
    /// (draft-ietf-oauth-sd-jwt-vc-27 §5.7) as required by policy: retrieve the <c>vct</c>'s document and its
    /// <c>extends</c> chain through <see cref="TypeMetadataProcessingOptions.Resolver"/>, check <c>vct#integrity</c> and
    /// each <c>extends#integrity</c> (§6) and each document's <c>vct</c> (§5.3), refuse cycles and over-deep chains
    /// (§7.4), merge claim and display metadata (§5.5.2, §5.6.5), and validate the credential against the merged claim
    /// metadata (§5.6): the <c>path</c>s, <c>mandatory</c> and <c>sd</c>, judged on the credential as issued, so a
    /// withheld selectively disclosable claim is not a missing mandatory one.
    /// </summary>
    /// <remarks>
    /// Metadata is retrieved only after the issuer signature and every profile rule have passed, so an unauthenticated
    /// presentation never makes the resolver fetch anything. A failure returns <see cref="SdJwtVcVerificationResult.IsValid"/>
    /// <c>false</c> with a stable code: <c>VC_TYPE_METADATA_UNAVAILABLE</c>, <c>VC_TYPE_METADATA_INVALID</c>,
    /// <c>VC_TYPE_METADATA_INTEGRITY_INVALID</c>, <c>VC_TYPE_METADATA_INTEGRITY_MISMATCH</c>,
    /// <c>VC_TYPE_METADATA_VCT_MISMATCH</c>, <c>VC_TYPE_METADATA_EXTENDS_CYCLE</c>, <c>VC_TYPE_METADATA_EXTENDS_DEPTH</c>,
    /// <c>VC_CLAIM_METADATA_INVALID</c>, <c>VC_CLAIM_METADATA_OVERRIDE_INVALID</c>, <c>VC_CLAIM_PATH_INVALID</c>,
    /// <c>VC_CLAIM_MANDATORY_MISSING</c> or <c>VC_CLAIM_SD_VIOLATION</c>. A resolver that throws gives
    /// <c>VC_TYPE_METADATA_RESOLVER_FAULT</c> and sets <see cref="SdJwtVcVerificationResult.TypeMetadataResolverFault"/>:
    /// a fault, not a verdict. A cancellation of <paramref name="cancellationToken"/> propagates.
    /// </remarks>
    /// <param name="presentation">The presented SD-JWT VC (issuer JWT, disclosures, optional KB-JWT).</param>
    /// <param name="resolveIssuerPublicJwk">Maps the issuer-JWT <c>kid</c> (empty when absent) to the Issuer's public JWK.</param>
    /// <param name="typeMetadata">The Type Metadata processing options, with the document resolver.</param>
    /// <param name="options">SD-JWT verification/Key-Binding policy; <c>null</c> uses the defaults.</param>
    /// <param name="cryptoProvider">The crypto provider; <c>null</c> uses a fresh <see cref="JoseCryptoProvider"/>.</param>
    /// <param name="cancellationToken">Cancels Type Metadata retrieval.</param>
    public static async Task<SdJwtVcVerificationResult> VerifyWithTypeMetadataAsync(
        string presentation,
        Func<string, Jwk?> resolveIssuerPublicJwk,
        TypeMetadataProcessingOptions typeMetadata,
        SdJwtVerificationOptions? options = null,
        IJoseCryptoProvider? cryptoProvider = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(presentation);
        ArgumentNullException.ThrowIfNull(resolveIssuerPublicJwk);
        ArgumentNullException.ThrowIfNull(typeMetadata);

        var verified = VerifyProfile(presentation, resolveIssuerPublicJwk, options, cryptoProvider);
        if (verified.Failure is { } failure)
            return failure;

        // The reconstruction step 2 ran, repeated with a trace of where each claim came from: the positions claim
        // metadata is judged on (§5.6). Same inputs, so it succeeds as it did there.
        var trace = new ReconstructionTrace();
        var signed = verified.IssuerJwt!.Payload;
        var traced = SdJwtReconstructor.Reconstruct(signed, verified.Components!.Disclosures, SdJwtClaims.ResolveSdAlg(signed), trace);

        var outcome = await TypeMetadataProcessor.ProcessAsync(
            signed, traced, trace, allDisclosuresPresent: false, typeMetadata, cancellationToken).ConfigureAwait(false);
        if (outcome.Fault is { } fault)
            return SdJwtVcVerificationResult.Faulted(outcome.Error!, fault);
        if (outcome.Error is { } error)
            return SdJwtVcVerificationResult.Failure(error);

        return SdJwtVcVerificationResult.Success(
            verified.Disclosed!, verified.Vct!, outcome.LeafDocument!, outcome.Metadata!, verified.KeyBindingVerified);
    }

    /// <summary>What the profile verification established, or the failure that stopped it.</summary>
    private sealed record Verified(
        SdJwtVcVerificationResult? Failure,
        SdJwtComponents? Components = null,
        CompactJwt? IssuerJwt = null,
        JsonObject? Disclosed = null,
        string? Vct = null,
        bool KeyBindingVerified = false);

    /// <summary>Steps 1 to 5: the media type, the generic SD-JWT verification and the profile's claim rules.</summary>
    private static Verified VerifyProfile(
        string presentation,
        Func<string, Jwk?> resolveIssuerPublicJwk,
        SdJwtVerificationOptions? options,
        IJoseCryptoProvider? cryptoProvider)
    {

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
            return new(SdJwtVcVerificationResult.Failure($"MALFORMED: {ex.Message}"));
        }

        var typ = issuerJwt.Type;
        if (!string.Equals(typ, SdJwtVcConstants.MediaType, StringComparison.Ordinal))
        {
            return new(SdJwtVcVerificationResult.Failure(
                $"VC_MEDIA_TYPE_INVALID: SD-JWT VC issuer-JWT 'typ' must be '{SdJwtVcConstants.MediaType}'; " +
                $"found '{typ ?? "(absent)"}' ({SdJwtVcConstants.Revision} §2.2.1)."));
        }

        // 2. Generic SD-JWT verification (signature, reconstruction, KB-JWT).
        var inner = SdJwtVerifier.Verify(presentation, resolveIssuerPublicJwk, options, cryptoProvider);
        if (!inner.IsValid || inner.DisclosedPayload is not { } disclosed)
            return new(SdJwtVcVerificationResult.Failure(inner.Errors.Count > 0 ? inner.Errors : ["VERIFICATION_FAILED"]));

        // 3. No registered must-not-disclose claim, nor any of its subclaims, may have been selectively disclosed
        //    (§2.2.2.3). The rule is positional and reads what the issuer signed: each reserved claim comes from the
        //    signed payload's clear top level, and its signed value holds no disclosure site at any depth, whether
        //    the Disclosure is presented, withheld or a decoy (a member of status or cnf under any name, an element
        //    of aka_vcts, and so on down). A claim elsewhere that only shares a reserved name, such as
        //    credentialSubject.status, is an ordinary claim. issuerJwt is the JWT whose signature step 2 verified:
        //    both parsed the same presentation string.
        foreach (var name in SdJwtVcConstants.MustNotBeSelectivelyDisclosed)
        {
            if (SdJwtVcClaimRules.SelectiveDisclosureViolation(issuerJwt.Payload, disclosed, name) is { } violation)
            {
                return new(SdJwtVcVerificationResult.Failure(
                    $"VC_DISALLOWED_DISCLOSURE: SD-JWT VC claim '{name}' {violation} ({SdJwtVcConstants.Revision} §2.2.2.3)."));
            }
        }

        // 4. vct REQUIRED, a non-empty string, present in the (cleared) disclosed payload (§2.2.2.1).
        if (!disclosed.TryGetPropertyValue(SdJwtVcConstants.VctClaim, out var vctNode)
            || SdJwtVcClaimRules.ReadTypeValue(vctNode) is not { } vct)
        {
            return new(SdJwtVcVerificationResult.Failure(
                $"VC_VCT_MISSING: SD-JWT VC payload has no non-empty string 'vct' claim ({SdJwtVcConstants.Revision} §2.2.2.1)."));
        }

        // 5. aka_vcts OPTIONAL; when present, a non-empty array of strings without the vct value (§2.2.2.2).
        //    Checked on the issuer-signed value, which step 3 left free of disclosure sites, so the holder's
        //    choice of Disclosures cannot change what is checked.
        if (SdJwtVcClaimRules.AkaVctsViolation(issuerJwt.Payload, vct) is { } akaVctsViolation)
        {
            return new(SdJwtVcVerificationResult.Failure(
                $"VC_AKA_VCTS_INVALID: SD-JWT VC claim 'aka_vcts' {akaVctsViolation} ({SdJwtVcConstants.Revision} §2.2.2.2)."));
        }

        return new(null, components, issuerJwt, disclosed, vct, inner.KeyBindingVerified);
    }
}
