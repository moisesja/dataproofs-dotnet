using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// The SD-JWT VC claim-format rules shared by <see cref="SdJwtVcIssuer"/> and <see cref="SdJwtVcVerifier"/>,
/// so issuance and verification enforce the same shape.
/// </summary>
internal static class SdJwtVcClaimRules
{
    /// <summary>
    /// Checks the OPTIONAL <c>aka_vcts</c> claim of <paramref name="payload"/> (draft-ietf-oauth-sd-jwt-vc-27
    /// §2.2.2.2): when present, it MUST be a non-empty array of strings, and the array MUST NOT contain the
    /// <c>vct</c> value. Each value MUST be a Collision-Resistant Name, which cannot be checked syntactically;
    /// an empty string is refused, as it is for <c>vct</c>.
    /// </summary>
    /// <param name="payload">The claims set (issuance) or the processed payload (verification).</param>
    /// <param name="vct">The credential's <c>vct</c> value, already validated.</param>
    /// <returns><c>null</c> when <c>aka_vcts</c> is absent or well formed; otherwise the reason it is not.</returns>
    public static string? AkaVctsViolation(JsonObject payload, string vct)
    {
        if (!payload.TryGetPropertyValue(SdJwtVcConstants.AkaVctsClaim, out var node))
            return null;

        if (node is not JsonArray array || array.Count == 0)
            return "must be a non-empty array of strings";

        foreach (var element in array)
        {
            if (element is not JsonValue value || !value.TryGetValue<string>(out var type) || type.Length == 0)
                return "must contain only non-empty strings";
            if (string.Equals(type, vct, StringComparison.Ordinal))
                return "must not contain the 'vct' value";
        }

        return null;
    }
}
