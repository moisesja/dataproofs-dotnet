using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Signing;

namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// Issues SD-JWT VCs (draft-ietf-oauth-sd-jwt-vc-27 §2): the SD-JWT VC profile layered on the
/// generic SD-JWT issuance (FR-16). Enforces the profile rules at issuance time — the
/// issuer-JWT <c>typ</c> is fixed to <see cref="SdJwtVcConstants.MediaType"/> (<c>dc+sd-jwt</c>, §2.2.1),
/// the <c>vct</c> claim is REQUIRED and stays in the clear (§2.2.2.1), an <c>aka_vcts</c> claim is
/// well formed when present (§2.2.2.2), and none of the registered must-not-disclose claims may be
/// marked selectively disclosable (§2.2.2.3) — and otherwise reuses <see cref="SdJwtIssuer"/>
/// unchanged. Stateless and thread-safe.
/// </summary>
public static class SdJwtVcIssuer
{
    /// <summary>
    /// Issue an SD-JWT VC from an input claims set and disclosure frame. The claims set MUST carry
    /// a non-empty string <c>vct</c>, and an <c>aka_vcts</c> claim, when present, MUST be a non-empty
    /// array of non-empty strings that does not contain the <c>vct</c> value; the frame MUST NOT mark
    /// any registered must-not-disclose claim (<see cref="SdJwtVcConstants.MustNotBeSelectivelyDisclosed"/>)
    /// as disclosable. Each violation is a documented failure (<see cref="MalformedJoseException"/>) — the
    /// disallowed claim shape the profile rejects.
    /// </summary>
    /// <param name="claims">The input claims set (a JSON object). Not mutated.</param>
    /// <param name="frame">Which claims are selectively disclosable (must not target registered claims).</param>
    /// <param name="signer">The Issuer's NetCrypto-backed JWS signer.</param>
    /// <param name="options">Issuance options (hash algorithm, decoys, holder cnf key).</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    /// <exception cref="MalformedJoseException">When <c>vct</c> is missing/blank, <c>aka_vcts</c> is malformed, or the frame discloses a disallowed claim.</exception>
    public static Task<SdJwtIssuer.Result> IssueAsync(
        JsonObject claims,
        DisclosureFrame frame,
        JwsSigner signer,
        SdJwtIssuerOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(frame);

        // vct REQUIRED and a non-empty string, in the clear (§2.2.2.1).
        if (!claims.TryGetPropertyValue(SdJwtVcConstants.VctClaim, out var vctNode)
            || vctNode is not JsonValue vctValue
            || vctValue.GetValueKind() != JsonValueKind.String
            || string.IsNullOrEmpty(vctValue.GetValue<string>()))
        {
            throw new MalformedJoseException(
                $"SD-JWT VC requires a non-empty string 'vct' claim in the clear ({SdJwtVcConstants.Revision} §2.2.2.1).");
        }

        // aka_vcts OPTIONAL; when present, a non-empty array of strings without the vct value (§2.2.2.2).
        if (SdJwtVcClaimRules.AkaVctsViolation(claims, vctValue.GetValue<string>()) is { } akaVctsViolation)
        {
            throw new MalformedJoseException(
                $"SD-JWT VC claim 'aka_vcts' {akaVctsViolation} ({SdJwtVcConstants.Revision} §2.2.2.2).");
        }

        // No registered must-not-disclose claim may be made selectively disclosable (§2.2.2.3).
        var disclosable = new HashSet<string>(frame.Entries.Keys, StringComparer.Ordinal);
        foreach (var reserved in SdJwtVcConstants.MustNotBeSelectivelyDisclosed)
        {
            if (disclosable.Contains(reserved))
                throw new MalformedJoseException(
                    $"SD-JWT VC claim '{reserved}' MUST NOT be selectively disclosed ({SdJwtVcConstants.Revision} §2.2.2.3); remove it from the DisclosureFrame.");
        }

        // typ is fixed to the SD-JWT VC media type; everything else is the generic SD-JWT pipeline.
        return SdJwtIssuer.IssueAsync(
            claims, frame, signer, options, typ: SdJwtVcConstants.MediaType, cancellationToken);
    }
}
