namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// The result of resolving a verification-method URL (FR-7): the public key material,
/// the controller identifier, and the controller metadata FR-3's authorization check
/// consumes — the set of verification relationships under which the controller document
/// lists the method, and whether the controller document actually controls it.
/// </summary>
public sealed record ResolvedVerificationMethod
{
    private readonly IReadOnlySet<string> _relationships = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>The verification method id (URL). Matched ordinally against the proof's <c>verificationMethod</c>.</summary>
    public required string Id { get; init; }

    /// <summary>The identifier of the controller declared by the verification method.</summary>
    public required string Controller { get; init; }

    /// <summary>The public key material of the method (Multikey canonical; JWK accepted — FR-8).</summary>
    public required PublicKeyMaterial PublicKey { get; init; }

    /// <summary>
    /// The verification relationships (e.g. <c>assertionMethod</c>, <c>authentication</c>,
    /// <c>capabilityInvocation</c>, <c>capabilityDelegation</c>, <c>keyAgreement</c>) under
    /// which the controller's document lists this method. Compared ordinally against the
    /// proof's <c>proofPurpose</c>.
    /// </summary>
    public required IReadOnlySet<string> Relationships
    {
        get => _relationships;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            _relationships = new HashSet<string>(value, StringComparer.Ordinal);
        }
    }

    /// <summary>
    /// <c>true</c> when the controller's document actually controls the method (the
    /// document includes the method and the method names that document's subject as its
    /// controller). Defaults to <c>true</c>; resolvers set <c>false</c> to signal a
    /// method whose claimed controller does not control it.
    /// </summary>
    public bool ControllerControlsMethod { get; init; } = true;
}
