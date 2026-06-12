namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// Verifier-supplied expectations for proof verification (FR-3). Unset members are not
/// checked.
/// </summary>
public sealed record ProofVerificationOptions
{
    /// <summary>
    /// When set, every proof's <c>proofPurpose</c> must equal this value; a mismatch
    /// fails with <see cref="ProofProblemCodes.ProofVerificationError"/> (distinct from
    /// the controller-authorization failure, which is
    /// <see cref="ProofProblemCodes.InvalidVerificationMethod"/>).
    /// </summary>
    public string? ExpectedProofPurpose { get; init; }

    /// <summary>When set, every proof's <c>domain</c> must equal this value
    /// (<see cref="ProofProblemCodes.InvalidDomainError"/> otherwise).</summary>
    public string? ExpectedDomain { get; init; }

    /// <summary>When set, every proof's <c>challenge</c> must equal this value
    /// (<see cref="ProofProblemCodes.InvalidChallengeError"/> otherwise).</summary>
    public string? ExpectedChallenge { get; init; }

    /// <summary>
    /// The instant against which <c>expires</c> is evaluated. Defaults to the current
    /// UTC time; settable for deterministic testing.
    /// </summary>
    public DateTimeOffset? VerificationTime { get; init; }
}
