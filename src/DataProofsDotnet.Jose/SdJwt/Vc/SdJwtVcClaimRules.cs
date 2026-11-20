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
    /// verification (<see cref="DisallowedDisclosure"/>) both decide by this one test.
    /// </summary>
    public static bool IsReserved(string topLevelClaim)
        => SdJwtVcConstants.MustNotBeSelectivelyDisclosed.Contains(topLevelClaim, StringComparer.Ordinal);

    /// <summary>
    /// Applies the must-not-disclose rule (draft-ietf-oauth-sd-jwt-vc-27 §2.2.2.3) to a verified presentation. Two
    /// checks together cover each registered claim and everything inside it:
    /// <list type="number">
    /// <item>Positions: a presented Disclosure whose claim path starts at a reserved claim is refused. That is the
    /// reserved claim itself, a Disclosure inside it under any name or as an array element, and anything inside a
    /// reserved claim that is itself a Disclosure.</item>
    /// <item>The signed payload: a reserved claim in the clear that carries selective-disclosure structure anywhere
    /// inside it, an <c>_sd</c> key or a <c>{"...": digest}</c> array placeholder, is refused whether or not the
    /// Disclosure it refers to was presented (<see cref="ReservedClaimWithDisclosureStructure"/>). A withheld
    /// Disclosure has no position, and withholding one changes the reserved claim's value under the same signature,
    /// such as an element dropped from <c>aka_vcts</c> or <c>status.status_list</c> dropped from <c>status</c>.
    /// A decoy digest there cannot be told from a withheld Disclosure, so it is refused as well.</item>
    /// </list>
    /// A Disclosure referenced from the top-level <c>_sd</c> hides its claim name behind its digest, so only the
    /// first check can see it, and only when it is presented.
    /// </summary>
    /// <param name="signedPayload">The Issuer-signed JWT payload, after its signature verified.</param>
    /// <param name="positions">Where the reconstruction resolved each presented Disclosure.</param>
    /// <returns>The reason the presentation is refused, or <c>null</c> when the rule holds.</returns>
    public static string? DisallowedDisclosure(JsonObject signedPayload, IReadOnlyList<DisclosurePosition> positions)
    {
        foreach (var position in positions)
        {
            var claim = position.TopLevelClaim;
            if (!IsReserved(claim))
                continue;

            return position.Path.Count == 1
                ? $"SD-JWT VC claim '{claim}' MUST NOT be selectively disclosed ({SdJwtVcConstants.Revision} §2.2.2.3)."
                : $"a Disclosure at '{position}' is inside SD-JWT VC claim '{claim}', whose subclaims MUST NOT be "
                  + $"selectively disclosed either ({SdJwtVcConstants.Revision} §2.2.2.3).";
        }

        if (ReservedClaimWithDisclosureStructure(signedPayload) is { } structured)
        {
            return $"SD-JWT VC claim '{structured}' carries an '_sd' digest array or a '...' array placeholder, so part "
                + "of it was made selectively disclosable, which it MUST NOT be, whether or not that Disclosure is "
                + $"presented ({SdJwtVcConstants.Revision} §2.2.2.3).";
        }

        return null;
    }

    /// <summary>
    /// The first reserved top-level claim of <paramref name="payload"/> whose value carries SD-JWT selective-disclosure
    /// structure anywhere inside it: an object with an <c>_sd</c> key, or an array element that is an object whose only
    /// member is <c>...</c> (the shapes RFC 9901 §7.1 step 3.b identifies as embedded digests). The issuer checks the
    /// claims set it is about to sign, and the verifier the payload that was signed. The walk is iterative, so a deep
    /// caller-built claims set cannot exhaust the stack.
    /// </summary>
    /// <returns>The claim's name, or <c>null</c> when every reserved claim present is plain JSON.</returns>
    public static string? ReservedClaimWithDisclosureStructure(JsonObject payload)
    {
        foreach (var (claim, value) in payload)
        {
            if (IsReserved(claim) && HasDisclosureStructure(value))
                return claim;
        }
        return null;
    }

    private static bool HasDisclosureStructure(JsonNode? root)
    {
        var pending = new Stack<JsonNode?>();
        pending.Push(root);
        while (pending.TryPop(out var node))
        {
            switch (node)
            {
                case JsonObject obj:
                    if (obj.ContainsKey("_sd"))
                        return true;
                    foreach (var (_, member) in obj)
                        pending.Push(member);
                    break;

                case JsonArray array:
                    foreach (var element in array)
                    {
                        if (element is JsonObject { Count: 1 } candidate && candidate.ContainsKey("..."))
                            return true;
                        pending.Push(element);
                    }
                    break;
            }
        }
        return false;
    }

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
