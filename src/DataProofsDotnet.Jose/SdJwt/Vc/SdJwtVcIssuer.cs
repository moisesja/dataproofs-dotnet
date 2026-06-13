using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Signing;

namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// Issues SD-JWT VCs (draft-ietf-oauth-sd-jwt-vc-16 §3): the SD-JWT VC profile layered on the
/// generic SD-JWT issuance (FR-16). Enforces the profile rules at issuance time — the
/// issuer-JWT <c>typ</c> is fixed to <see cref="SdJwtVcConstants.MediaType"/> (<c>dc+sd-jwt</c>),
/// the <c>vct</c> claim is REQUIRED and stays in the clear, and none of the registered
/// must-not-disclose claims may be marked selectively disclosable — and otherwise reuses
/// <see cref="SdJwtIssuer"/> unchanged. Stateless and thread-safe.
/// </summary>
public static class SdJwtVcIssuer
{
    /// <summary>
    /// Issue an SD-JWT VC from an input claims set and disclosure frame. The claims set MUST carry
    /// a non-empty string <c>vct</c>; the frame MUST NOT mark any registered must-not-disclose
    /// claim (<see cref="SdJwtVcConstants.MustNotBeSelectivelyDisclosed"/>) as disclosable. Either
    /// violation is a documented failure (<see cref="MalformedJoseException"/>) — the disallowed
    /// claim shape the profile rejects.
    /// </summary>
    /// <param name="claims">The input claims set (a JSON object). Not mutated.</param>
    /// <param name="frame">Which claims are selectively disclosable (must not target registered claims).</param>
    /// <param name="signer">The Issuer's NetCrypto-backed JWS signer.</param>
    /// <param name="options">Issuance options (hash algorithm, decoys, holder cnf key).</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    /// <exception cref="MalformedJoseException">When <c>vct</c> is missing/blank or the frame discloses a disallowed claim.</exception>
    public static Task<SdJwtIssuer.Result> IssueAsync(
        JsonObject claims,
        DisclosureFrame frame,
        JwsSigner signer,
        SdJwtIssuerOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(frame);

        // vct REQUIRED and a non-empty string, in the clear (§3.2.2.1.1).
        if (!claims.TryGetPropertyValue(SdJwtVcConstants.VctClaim, out var vctNode)
            || vctNode is not JsonValue vctValue
            || vctValue.GetValueKind() != JsonValueKind.String
            || string.IsNullOrEmpty(vctValue.GetValue<string>()))
        {
            throw new MalformedJoseException(
                "SD-JWT VC requires a non-empty string 'vct' claim in the clear (draft-ietf-oauth-sd-jwt-vc-16 §3.2.2.1.1).");
        }

        // No registered must-not-disclose claim may be made selectively disclosable (§3.2.2.2).
        var disclosable = new HashSet<string>(frame.Entries.Keys, StringComparer.Ordinal);
        foreach (var reserved in SdJwtVcConstants.MustNotBeSelectivelyDisclosed)
        {
            if (disclosable.Contains(reserved))
                throw new MalformedJoseException(
                    $"SD-JWT VC claim '{reserved}' MUST NOT be selectively disclosed (draft-ietf-oauth-sd-jwt-vc-16 §3.2.2.2); remove it from the DisclosureFrame.");
        }

        // typ is fixed to the SD-JWT VC media type; everything else is the generic SD-JWT pipeline.
        return SdJwtIssuer.IssueAsync(
            claims, frame, signer, options, typ: SdJwtVcConstants.MediaType, cancellationToken);
    }
}
