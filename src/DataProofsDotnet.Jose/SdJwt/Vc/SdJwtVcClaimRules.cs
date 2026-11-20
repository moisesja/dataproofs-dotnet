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
    /// The registered claims whose must-not-disclose rule (draft-ietf-oauth-sd-jwt-vc-27 §2.2.2.3) the verifier
    /// enforces by position, with <see cref="SelectiveDisclosureViolation"/>, rather than by matching Disclosure
    /// names at any depth. Only <c>aka_vcts</c> so far; issue #48 moves the other names here.
    /// </summary>
    public static readonly IReadOnlySet<string> EnforcedByPosition = new HashSet<string>(StringComparer.Ordinal)
    {
        SdJwtVcConstants.AkaVctsClaim,
    };

    /// <summary>
    /// Checks, by position, that the registered top-level claim <paramref name="name"/> and its sub-claims were not
    /// made selectively disclosable (draft-ietf-oauth-sd-jwt-vc-27 §2.2.2.3: "including any of their subclaims").
    /// The claim may reach the processed payload only from the issuer-signed payload's clear top level, and its
    /// signed value may hold no disclosure site at any depth: no <c>_sd</c> digest array and no
    /// <c>{"...": digest}</c> array-element placeholder. The second test reads what the issuer signed, so it holds
    /// whether the holder presents the matching Disclosure, withholds it, or none exists (a decoy).
    /// A same-named claim nested in another claim is not the registered claim and is not affected.
    /// </summary>
    /// <param name="signedPayload">The issuer-signed JWT payload, before any Disclosure is applied.</param>
    /// <param name="processedPayload">The payload after the presented Disclosures were applied.</param>
    /// <param name="name">The registered claim name.</param>
    /// <returns><c>null</c> when the rule holds; otherwise the reason it does not.</returns>
    public static string? SelectiveDisclosureViolation(JsonObject signedPayload, JsonObject processedPayload, string name)
    {
        if (!signedPayload.TryGetPropertyValue(name, out var signedValue))
            return processedPayload.ContainsKey(name) ? "MUST NOT be selectively disclosed" : null;

        return HoldsDisclosureSite(signedValue) ? "MUST NOT have selectively disclosable sub-claims or elements" : null;
    }

    // Mirrors what SdJwtReconstructor resolves: an object's _sd member, and an array element that is an object
    // whose only member is "...". The signed payload was parsed at the default depth limit, so recursion is bounded.
    private static bool HoldsDisclosureSite(JsonNode? node) => node switch
    {
        JsonObject obj => obj.ContainsKey("_sd") || obj.Any(member => HoldsDisclosureSite(member.Value)),
        JsonArray array => array.Any(element =>
            (element is JsonObject placeholder && placeholder.Count == 1 && placeholder.ContainsKey("..."))
            || HoldsDisclosureSite(element)),
        _ => false,
    };

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
    /// Checks the OPTIONAL <c>aka_vcts</c> claim of <paramref name="payload"/> (draft-ietf-oauth-sd-jwt-vc-27
    /// §2.2.2.2): when present, it MUST be a non-empty array of strings (each read by
    /// <see cref="ReadTypeValue"/>), and the array MUST NOT contain the <c>vct</c> value.
    /// </summary>
    /// <param name="payload">
    /// The claims set (issuance) or the issuer-signed payload (verification), never the processed payload: what
    /// the holder presents must not change what is checked.
    /// </param>
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
