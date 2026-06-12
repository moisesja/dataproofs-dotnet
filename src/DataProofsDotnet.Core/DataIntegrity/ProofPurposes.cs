namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// The well-known <c>proofPurpose</c> values, matching the verification relationships a
/// controller document may list a verification method under. Data Integrity treats
/// purposes as open strings, so these are constants rather than an enum.
/// </summary>
public static class ProofPurposes
{
    /// <summary>The <c>assertionMethod</c> purpose.</summary>
    public const string AssertionMethod = "assertionMethod";

    /// <summary>The <c>authentication</c> purpose.</summary>
    public const string Authentication = "authentication";

    /// <summary>The <c>capabilityInvocation</c> purpose.</summary>
    public const string CapabilityInvocation = "capabilityInvocation";

    /// <summary>The <c>capabilityDelegation</c> purpose.</summary>
    public const string CapabilityDelegation = "capabilityDelegation";

    /// <summary>The <c>keyAgreement</c> purpose.</summary>
    public const string KeyAgreement = "keyAgreement";
}
