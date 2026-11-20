namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// The SD-JWT VC profile constants (draft-ietf-oauth-sd-jwt-vc-27): the media type, the type claims,
/// and the registered claims that MUST NOT be selectively disclosed. The pin is <c>-27</c>
/// (re-verified against the IETF datatracker 2026-11-19: -27 of 2026-11-16 is the latest, in IESG
/// Evaluation). All draft-sensitive values live here so a re-pin is localized (FR-17); the steps for
/// the next move, to the published RFC, are in PRD §12.2.
/// </summary>
public static class SdJwtVcConstants
{
    /// <summary>The pinned revision, as cited in failure messages. Internal so the RFC move edits one string.</summary>
    internal const string Revision = "draft-ietf-oauth-sd-jwt-vc-27";

    /// <summary>
    /// The SD-JWT VC issuer-JWT <c>typ</c> header value (§2.2.1), the subtype of the
    /// <c>application/dc+sd-jwt</c> media type (§2.1): <c>dc+sd-jwt</c>. This is what the Issuer
    /// produces and the only value the Verifier accepts. The Verifier compares it exactly (ordinal), so
    /// the spellings RFC 7515 §4.1.9 would treat as the same media type, <c>application/dc+sd-jwt</c> and
    /// case variants, are refused as well.
    /// </summary>
    public const string MediaType = "dc+sd-jwt";

    /// <summary>
    /// The former SD-JWT VC <c>typ</c> value, <c>vc+sd-jwt</c>. Drafts up to -18 asked Verifiers to accept it
    /// for a transitional period; -19 removed that, and -27 §2.2.1 requires <c>dc+sd-jwt</c>.
    /// <see cref="SdJwtVcVerifier"/> rejects it. <see cref="SdJwtVcIssuer"/> has never issued it.
    /// </summary>
    [Obsolete("draft-ietf-oauth-sd-jwt-vc-19 removed the transitional vc+sd-jwt typ and SdJwtVcVerifier no longer accepts it. "
        + "Use MediaType (dc+sd-jwt). W3C VC-JOSE-COSE uses vc+sd-jwt for a different format.")]
    public const string TransitionalMediaType = "vc+sd-jwt";

    /// <summary>The REQUIRED type claim naming the credential's type (§2.2.2.1).</summary>
    public const string VctClaim = "vct";

    /// <summary>
    /// The OPTIONAL claim listing the credential's additional types (§2.2.2.2): when present, a non-empty
    /// array of strings that does not contain the <see cref="VctClaim"/> value. A credential's types are
    /// the <c>vct</c> value and the <c>aka_vcts</c> values, and nothing else: Type Metadata and its
    /// <c>extends</c> property do not add types (§2.2.2.2, §5.4).
    /// </summary>
    public const string AkaVctsClaim = "aka_vcts";

    /// <summary>The OPTIONAL integrity-metadata claim binding the credential to its Type Metadata document (§2.2.2.3, §6).</summary>
    public const string VctIntegrityClaim = "vct#integrity";

    /// <summary>
    /// The OPTIONAL status claim (§2.2.2.3), defined by the Token Status List specification, which -22 made a
    /// normative reference. The verifier carries it in the payload and does not check it; §2.4 says a Verifier
    /// SHOULD check it, which is the consumer's step.
    /// </summary>
    public const string StatusClaim = "status";

    /// <summary>
    /// The registered JWT claims that, "including any of their subclaims", MUST NOT be placed in
    /// Disclosures, i.e. MUST stay in the clear in the SD-JWT payload (§2.2.2.3): <c>iss</c>,
    /// <c>nbf</c>, <c>exp</c>, <c>cnf</c>, <c>vct</c>, <c>vct#integrity</c>, <c>aka_vcts</c>,
    /// <c>status</c>. The names are those of top-level claims, and the rule covers each claim and
    /// everything inside it: a member of <c>status</c> or <c>cnf</c> at any depth, an element of
    /// <c>aka_vcts</c>. A <see cref="DisclosureFrame"/> entry on one of them, of any kind, is a
    /// disallowed claim shape the Issuer rejects. The Verifier judges the rule by position, on what the
    /// Issuer signed (<c>VC_DISALLOWED_DISCLOSURE</c>): it refuses a top-level reserved claim that a
    /// presented Disclosure supplied, and a signed reserved claim holding any disclosure site (an <c>_sd</c>
    /// digest or a <c>{"...": digest}</c> element placeholder) at any depth, whether its Disclosure is
    /// presented, withheld or a decoy. A claim deeper in the payload that only shares a name, such as
    /// <c>credentialSubject.status</c>, is an ordinary claim and may be selectively disclosed. A whole
    /// reserved claim behind a top-level digest whose Disclosure the holder withholds cannot be told from a
    /// decoy, so such a credential verifies without that claim: keeping these claims in the clear is the
    /// Issuer's duty.
    /// </summary>
    public static readonly IReadOnlyList<string> MustNotBeSelectivelyDisclosed =
        ["iss", "nbf", "exp", "cnf", VctClaim, VctIntegrityClaim, AkaVctsClaim, StatusClaim];
}
