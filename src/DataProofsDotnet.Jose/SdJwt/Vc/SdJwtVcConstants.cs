namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// The SD-JWT VC profile constants (draft-ietf-oauth-sd-jwt-vc-16): media types, the type claim,
/// and the registered claims that MUST NOT be selectively disclosed. The pin is
/// <c>-16</c> (re-verified against the IETF datatracker 2026-06-12: -16 remains the latest, no
/// -17 exists). All draft-sensitive values live here so a re-pin is localized (FR-17).
/// </summary>
public static class SdJwtVcConstants
{
    /// <summary>
    /// The SD-JWT VC media type and issuer-JWT <c>typ</c> header value (§3.2.2.2 / §3.5):
    /// <c>dc+sd-jwt</c>. This is what the Issuer produces and the Verifier requires.
    /// </summary>
    public const string MediaType = "dc+sd-jwt";

    /// <summary>
    /// The transitional, deprecated media type (<c>vc+sd-jwt</c>) accepted on <b>input</b> only
    /// (draft history; older issuers). The Issuer never produces it.
    /// </summary>
    public const string TransitionalMediaType = "vc+sd-jwt";

    /// <summary>The REQUIRED type claim naming the credential's type (§3.2.2.1.1).</summary>
    public const string VctClaim = "vct";

    /// <summary>The OPTIONAL integrity-metadata claim binding the credential to its Type Metadata document (§3.2.2.1.1).</summary>
    public const string VctIntegrityClaim = "vct#integrity";

    /// <summary>The OPTIONAL status claim (§3.2.2.2).</summary>
    public const string StatusClaim = "status";

    /// <summary>
    /// The registered JWT claims that MUST NOT be placed in Disclosures, i.e. MUST stay in the
    /// clear in the SD-JWT payload (§3.2.2.2): <c>iss</c>, <c>nbf</c>, <c>exp</c>, <c>cnf</c>,
    /// <c>vct</c>, <c>vct#integrity</c>, <c>status</c>. Marking any of these in a
    /// <see cref="DisclosureFrame"/> is a disallowed claim shape the Issuer rejects, and finding
    /// any of them disclosed in a presentation is a Verifier failure.
    /// </summary>
    public static readonly IReadOnlyList<string> MustNotBeSelectivelyDisclosed =
        ["iss", "nbf", "exp", "cnf", VctClaim, VctIntegrityClaim, StatusClaim];
}
