namespace DataProofsDotnet.DataIntegrity;

/// <summary>The verification outcome for a single proof (FR-3).</summary>
public sealed record ProofVerificationResult
{
    /// <summary><c>true</c> when the proof verified successfully.</summary>
    public required bool Verified { get; init; }

    /// <summary>The proof this result refers to, when it could be parsed.</summary>
    public DataIntegrityProof? Proof { get; init; }

    /// <summary>The problems that caused verification to fail; empty on success.</summary>
    public IReadOnlyList<ProofProblem> Problems { get; init; } = [];

    /// <summary>Creates a successful result.</summary>
    public static ProofVerificationResult Success(DataIntegrityProof? proof = null)
        => new() { Verified = true, Proof = proof };

    /// <summary>Creates a failed result carrying a single problem detail.</summary>
    public static ProofVerificationResult Failure(string code, string? message = null, DataIntegrityProof? proof = null)
        => new()
        {
            Verified = false,
            Proof = proof,
            Problems = [new ProofProblem { Code = code, Message = message }],
        };
}
