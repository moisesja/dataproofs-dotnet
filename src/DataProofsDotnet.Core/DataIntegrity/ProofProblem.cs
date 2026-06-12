namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// A problem detail describing why verification failed (FR-3). Messages are diagnostic
/// only and never contain secrets, key material, or document payloads.
/// </summary>
public sealed record ProofProblem
{
    /// <summary>The problem code; one of the <see cref="ProofProblemCodes"/> constants.</summary>
    public required string Code { get; init; }

    /// <summary>A human-readable description of the problem.</summary>
    public string? Message { get; init; }
}
