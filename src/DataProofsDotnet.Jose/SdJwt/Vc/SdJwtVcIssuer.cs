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
    /// an <c>_sd</c> key or a <c>...</c> array placeholder the caller built inside one is refused, as the verifier
    /// would refuse it.
    /// </summary>
    /// <param name="claims">The input claims set (a JSON object). Not mutated.</param>
    /// <param name="frame">Which claims are selectively disclosable (must not target registered claims or their subclaims).</param>
    /// <param name="signer">The Issuer's NetCrypto-backed JWS signer.</param>
    /// <param name="options">Issuance options (hash algorithm, decoys, holder cnf key).</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    /// <exception cref="MalformedJoseException">When <c>vct</c> is missing/blank, <c>aka_vcts</c> is malformed, the frame discloses a disallowed claim, or a reserved claim carries selective-disclosure structure.</exception>
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

        // The same rule for the claims set itself: a reserved claim must reach the signer as plain JSON. An '_sd' key
        // or '...' placeholder the caller built inside one would be signed as it is, and the verifier refuses it.
        if (SdJwtVcClaimRules.ReservedClaimWithDisclosureStructure(claims) is { } structured)
        {
            throw new MalformedJoseException(
                $"SD-JWT VC claim '{structured}' carries an '_sd' digest array or a '...' array placeholder; it and its "
                + $"subclaims MUST NOT be selectively disclosed ({SdJwtVcConstants.Revision} §2.2.2.3). Pass it as plain JSON.");
        }

        // typ is fixed to the SD-JWT VC media type; everything else is the generic SD-JWT pipeline.
        return SdJwtIssuer.IssueAsync(
            claims, frame, signer, options, typ: SdJwtVcConstants.MediaType, cancellationToken);
    }
}
