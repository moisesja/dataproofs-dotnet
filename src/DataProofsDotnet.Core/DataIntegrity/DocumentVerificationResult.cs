namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// The verification outcome for a secured document, covering every proof it carries
/// (proof sets and chains, FR-6).
/// </summary>
public sealed record DocumentVerificationResult
{
    /// <summary>
    /// <c>true</c> only when the document carries at least one proof, every proof
    /// verified, and no document-level problem occurred (fail-closed aggregation;
    /// per-proof outcomes are in <see cref="ProofResults"/>).
    /// </summary>
    public required bool Verified { get; init; }

    /// <summary>Per-proof verification results, in document order.</summary>
    public IReadOnlyList<ProofVerificationResult> ProofResults { get; init; } = [];

    /// <summary>Document-level problems (e.g. a missing or malformed <c>proof</c> member).</summary>
    public IReadOnlyList<ProofProblem> Problems { get; init; } = [];
}
