using System.Text;
using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// The SD-JWT VC claim-format rules shared by <see cref="SdJwtVcIssuer"/> and <see cref="SdJwtVcVerifier"/>,
/// so issuance and verification enforce the same shape.
/// </summary>
internal static class SdJwtVcClaimRules
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Reads a credential type value (<c>vct</c>, or one element of <c>aka_vcts</c>): a non-empty JSON
    /// string that is well-formed UTF-16. Each such value MUST be a Collision-Resistant Name
    /// (draft-ietf-oauth-sd-jwt-vc-27 §2.2.2.1, §2.2.2.2), which cannot be checked syntactically; an
    /// empty string is refused. So is a lone surrogate: it is not text, the JSON writer would sign U+FFFD in
    /// its place, and two different .NET strings could then sign as the same type. Only a caller-built claims
    /// set can carry one, since every decoder refuses it on the wire (issues #28, #30).
    /// </summary>
    /// <returns>The value, or <c>null</c> when <paramref name="node"/> is not such a string.</returns>
    public static string? ReadTypeValue(JsonNode? node)
    {
        if (node is not JsonValue value)
            return null;

        string? type;
        try
        {
            if (!value.TryGetValue(out type))
                return null;
        }
        catch (InvalidOperationException)
        {
            // A string parsed from an unpaired-surrogate escape cannot be read as a .NET string.
            return null;
        }

        if (type.Length == 0)
            return null;
        try
        {
            StrictUtf8.GetByteCount(type);
        }
        catch (EncoderFallbackException)
        {
            return null;
        }
        return type;
    }

    /// <summary>
    /// Whether <paramref name="topLevelClaim"/>, the name of a member of the top-level claims set, is one of the
    /// registered claims that, "including any of their subclaims", MUST NOT be included in Disclosures
    /// (draft-ietf-oauth-sd-jwt-vc-27 §2.2.2.3, <see cref="SdJwtVcConstants.MustNotBeSelectivelyDisclosed"/>).
    /// The list names JWT claims, which are top-level members: a claim deeper in the payload that has one of
    /// these names is an ordinary claim. Issuance (a <see cref="DisclosureFrame"/>'s top-level names) and
    /// verification (<see cref="ReservedClaimAt"/>) both decide by this one test.
    /// </summary>
    public static bool IsReserved(string topLevelClaim)
        => SdJwtVcConstants.MustNotBeSelectivelyDisclosed.Contains(topLevelClaim, StringComparer.Ordinal);

    /// <summary>
    /// The registered must-not-disclose claim that a Disclosure resolved at <paramref name="position"/> is, or sits
    /// inside (draft-ietf-oauth-sd-jwt-vc-27 §2.2.2.3): its top-level claim when <see cref="IsReserved"/> holds for
    /// it, whatever the Disclosure's own name or depth, whether it is an object property or an array element, and
    /// whether the reserved claim around it is in the clear or itself a Disclosure.
    /// </summary>
    /// <returns>The reserved claim's name, or <c>null</c> when the Disclosure sits outside every reserved claim.</returns>
    public static string? ReservedClaimAt(DisclosurePosition position)
        => IsReserved(position.TopLevelClaim) ? position.TopLevelClaim : null;

    /// <summary>
    /// Checks the OPTIONAL <c>aka_vcts</c> claim of <paramref name="payload"/> (draft-ietf-oauth-sd-jwt-vc-27
    /// §2.2.2.2): when present, it MUST be a non-empty array of strings (each read by
    /// <see cref="ReadTypeValue"/>), and the array MUST NOT contain the <c>vct</c> value.
    /// </summary>
    /// <param name="payload">The claims set (issuance) or the processed payload (verification).</param>
    /// <param name="vct">The credential's <c>vct</c> value, already read by <see cref="ReadTypeValue"/>.</param>
    /// <returns><c>null</c> when <c>aka_vcts</c> is absent or well formed; otherwise the reason it is not.</returns>
    public static string? AkaVctsViolation(JsonObject payload, string vct)
    {
        if (!payload.TryGetPropertyValue(SdJwtVcConstants.AkaVctsClaim, out var node))
            return null;

        if (node is not JsonArray array || array.Count == 0)
            return "must be a non-empty array of strings";

        foreach (var element in array)
        {
            if (ReadTypeValue(element) is not { } type)
                return "must contain only non-empty, well-formed strings";
            if (string.Equals(type, vct, StringComparison.Ordinal))
                return "must not contain the 'vct' value";
        }

        return null;
    }
}
