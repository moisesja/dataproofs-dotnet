using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Signing;

namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// Issues SD-JWT VCs (draft-ietf-oauth-sd-jwt-vc-27 §2): the SD-JWT VC profile layered on the
/// generic SD-JWT issuance (FR-16). Enforces the profile rules at issuance time — the
/// issuer-JWT <c>typ</c> is fixed to <see cref="SdJwtVcConstants.MediaType"/> (<c>dc+sd-jwt</c>, §2.2.1),
/// the <c>vct</c> claim is REQUIRED and stays in the clear (§2.2.2.1), an <c>aka_vcts</c> claim is
/// well formed when present (§2.2.2.2), and none of the registered must-not-disclose claims, nor
/// anything inside one, may be marked selectively disclosable (§2.2.2.3) — and otherwise reuses
/// <see cref="SdJwtIssuer"/> unchanged. Stateless and thread-safe.
/// </summary>
public static class SdJwtVcIssuer
{
    /// <summary>
    /// Issue an SD-JWT VC from an input claims set and disclosure frame. The claims set MUST carry
    /// a non-empty string <c>vct</c>, and an <c>aka_vcts</c> claim, when present, MUST be a non-empty
    /// array of non-empty strings that does not contain the <c>vct</c> value; the frame MUST NOT have a
    /// top-level entry, of any kind, on a registered must-not-disclose claim
    /// (<see cref="SdJwtVcConstants.MustNotBeSelectivelyDisclosed"/>), since every Disclosure such an entry
    /// makes is that claim or one of its subclaims. Each violation is a documented failure
    /// (<see cref="MalformedJoseException"/>) — the disallowed claim shape the profile rejects. A nested entry
    /// that only shares a reserved name, such as <c>DiscloseObjectProperties("credentialSubject", "status")</c>,
    /// is an ordinary claim and is issued. A reserved claim in <paramref name="claims"/> must also be plain JSON:
    /// an <c>_sd</c> digest array or a <c>...</c> array placeholder the caller built inside one, read as it will be
    /// signed, is refused, as the verifier would refuse it.
    /// </summary>
    /// <param name="claims">The input claims set (a JSON object). Not mutated.</param>
    /// <param name="frame">Which claims are selectively disclosable (must not target registered claims or their subclaims).</param>
    /// <param name="signer">The Issuer's NetCrypto-backed JWS signer.</param>
    /// <param name="options">Issuance options (hash algorithm, decoys, holder cnf key).</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    /// <exception cref="MalformedJoseException">
    /// When <c>vct</c> is missing/blank, <c>aka_vcts</c> is malformed, the frame discloses a disallowed claim, a reserved
    /// claim carries selective-disclosure structure, or <see cref="SdJwtIssuer.IssueAsync"/> refuses the SD-JWT, for
    /// example a present <c>nbf</c> or <c>exp</c> that is not a NumericDate, or is one outside -62135596800 to
    /// 253402300799 (the verifier's <c>SD_JWT_NBF_INVALID</c> / <c>SD_JWT_EXP_INVALID</c>). Their times are not
    /// judged: a credential valid from tomorrow is issued.
    /// </exception>
    public static Task<SdJwtIssuer.Result> IssueAsync(
        JsonObject claims,
        DisclosureFrame frame,
        JwsSigner signer,
        SdJwtIssuerOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(frame);

        // vct REQUIRED and a non-empty, well-formed string, in the clear (§2.2.2.1).
        if (!claims.TryGetPropertyValue(SdJwtVcConstants.VctClaim, out var vctNode)
            || SdJwtVcClaimRules.ReadTypeValue(vctNode) is not { } vct)
        {
            throw new MalformedJoseException(
                $"SD-JWT VC requires a non-empty, well-formed string 'vct' claim in the clear ({SdJwtVcConstants.Revision} §2.2.2.1).");
        }

        // aka_vcts OPTIONAL; when present, a non-empty array of strings without the vct value (§2.2.2.2).
        if (SdJwtVcClaimRules.AkaVctsViolation(claims, vct) is { } akaVctsViolation)
        {
            throw new MalformedJoseException(
                $"SD-JWT VC claim 'aka_vcts' {akaVctsViolation} ({SdJwtVcConstants.Revision} §2.2.2.2).");
        }

        // No registered must-not-disclose claim, nor any of its subclaims, may be made selectively disclosable
        // (§2.2.2.3). This is the verifier's positional rule applied to the frame: every Disclosure a top-level
        // entry produces (flat, structured, recursive or array element) resolves at or under that entry's claim, so
        // a reserved top-level name is refused whatever the entry's kind, and a nested entry is never reserved,
        // whatever its name (credentialSubject.status is an ordinary claim).
        foreach (var claim in frame.Entries.Keys)
        {
            if (SdJwtVcClaimRules.IsReserved(claim))
                throw new MalformedJoseException(
                    $"SD-JWT VC claim '{claim}' MUST NOT be selectively disclosed, and neither may any of its subclaims "
                    + $"({SdJwtVcConstants.Revision} §2.2.2.3); remove its entry from the DisclosureFrame.");
        }

        // The same rule for the claims set itself: a reserved claim must reach the signer as plain JSON. A disclosure
        // site the caller built inside one would be signed as it is, and the verifier refuses it. A JsonValue can wrap
        // a .NET object that only becomes a JSON object or array when serialized, and could serialize differently the
        // next time, so the claims are serialized once, that JSON is checked, and that JSON is what SdJwtIssuer signs.
        // The frame cannot change a reserved claim: the check above refused every entry on one.
        JsonObject asSigned;
        try
        {
            asSigned = JsonNode.Parse(
                CompactJwt.SerializePayload((JsonObject)claims.DeepClone()),
                documentOptions: new JsonDocumentOptions { AllowDuplicateProperties = false })!.AsObject();
        }
        catch (JsonException ex)
        {
            throw new MalformedJoseException(
                "The SD-JWT VC claims set does not serialize to a JSON object with unique member names (RFC 7519 §4).", ex);
        }
        catch (Exception ex)
        {
            // A claims set the serializer cannot write (too deep, a non-finite number, a throwing getter) failed inside
            // SdJwtIssuer's task before this check existed; it still fails there, not at the call.
            return Task.FromException<SdJwtIssuer.Result>(ex);
        }

        foreach (var (claim, value) in asSigned)
        {
            if (SdJwtVcClaimRules.IsReserved(claim) && SdJwtVcClaimRules.HoldsDisclosureSite(value))
            {
                throw new MalformedJoseException(
                    $"SD-JWT VC claim '{claim}' carries an '_sd' digest array or a '...' array placeholder; it and its "
                    + $"subclaims MUST NOT be selectively disclosed ({SdJwtVcConstants.Revision} §2.2.2.3). Pass it as plain JSON.");
            }
        }

        // typ is fixed to the SD-JWT VC media type; everything else is the generic SD-JWT pipeline, over the JSON
        // that was checked.
        return SdJwtIssuer.IssueAsync(
            asSigned, frame, signer, options, typ: SdJwtVcConstants.MediaType, cancellationToken);
    }

    /// <summary>
    /// Issue an SD-JWT VC as <see cref="IssueAsync"/> does, then check it against its Type Metadata
    /// (draft-ietf-oauth-sd-jwt-vc-27 §5): the SD-JWT VC verifier's own processing
    /// (<see cref="SdJwtVcVerifier.VerifyWithTypeMetadataAsync"/>) runs on the issued credential with every Disclosure,
    /// so a credential this returns passes that processing when the holder presents every Disclosure. The documents
    /// are retrieved through <see cref="TypeMetadataProcessingOptions.Resolver"/> for the signed <c>vct</c> and each
    /// <c>extends</c> value; a <c>vct#integrity</c> in <paramref name="claims"/> must match the <c>vct</c>'s document.
    /// Here every Disclosure is known, so a claim missing from an object whose digests are all decoys is missing, and a
    /// <c>mandatory</c> claim the claims set lacks is refused. The credential is never returned when the check fails.
    /// </summary>
    /// <param name="claims">The input claims set (a JSON object). Not mutated.</param>
    /// <param name="frame">Which claims are selectively disclosable.</param>
    /// <param name="signer">The Issuer's NetCrypto-backed JWS signer.</param>
    /// <param name="typeMetadata">The Type Metadata processing options, with the document resolver.</param>
    /// <param name="options">Issuance options (hash algorithm, decoys, holder cnf key).</param>
    /// <param name="cancellationToken">Cancels the signing operation and Type Metadata retrieval.</param>
    /// <exception cref="MalformedJoseException">
    /// When <see cref="IssueAsync"/> refuses the input, or when the credential fails Type Metadata processing; the
    /// message starts with the verifier's code (<c>VC_CLAIM_SD_VIOLATION</c>, <c>VC_TYPE_METADATA_INTEGRITY_MISMATCH</c>,
    /// and so on).
    /// </exception>
    /// <exception cref="JoseException">
    /// Exactly a <see cref="JoseException"/>, not a subtype, with the message starting
    /// <c>VC_TYPE_METADATA_RESOLVER_FAULT</c>, when the resolver threw: a fault, not a verdict on the credential. The
    /// resolver's exception is the inner exception.
    /// </exception>
    public static async Task<SdJwtIssuer.Result> IssueWithTypeMetadataAsync(
        JsonObject claims,
        DisclosureFrame frame,
        JwsSigner signer,
        TypeMetadataProcessingOptions typeMetadata,
        SdJwtIssuerOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(typeMetadata);

        var issued = await IssueAsync(claims, frame, signer, options, cancellationToken).ConfigureAwait(false);

        // Parity with the verifier: the same reconstruction, traced, over what was signed, with every Disclosure.
        // SdJwtIssuer has already reconstructed these bytes untraced and refused to sign anything that would not verify,
        // so this walk cannot fail; it is repeated only to record the positions claim metadata is judged on.
        var signed = CompactJwt.Decode(issued.IssuerJwt).Payload;
        var trace = new ReconstructionTrace();
        var processed = SdJwtReconstructor.Reconstruct(signed, issued.Disclosures, SdJwtClaims.ResolveSdAlg(signed), trace);

        var outcome = await TypeMetadataProcessor.ProcessAsync(
            signed, processed, trace, allDisclosuresPresent: true, typeMetadata, cancellationToken).ConfigureAwait(false);
        if (outcome.Fault is { } fault)
            throw new JoseException(outcome.Error!, fault);
        if (outcome.Error is { } error)
            throw new MalformedJoseException(error);

        return issued;
    }
}
