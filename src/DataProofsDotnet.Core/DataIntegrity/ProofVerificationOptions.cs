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

    /// <summary>
    /// When set, the secured document's <c>@context</c> values must all be among these context
    /// IRIs (VC Data Integrity 1.0 §4.6, Context Validation), checked after the proofs are
    /// verified, as the specification requires. A value that is not listed, or an inline context
    /// object, fails the document with a document-level
    /// <see cref="ProofProblemCodes.ProofVerificationError"/> beside the per-proof results.
    /// </summary>
    /// <remarks>
    /// A proof over RDF binds the statements, not the JSON that compacted them, so a holder can
    /// present a verified document under a <c>@context</c> that reads its terms differently
    /// (<c>boards</c> as <c>sails</c>). The specification's answer is that applications MUST accept
    /// only known contexts. Unset, nothing is checked and that duty stays with the application; a
    /// document without <c>@context</c> passes.
    /// </remarks>
    public IReadOnlyCollection<string>? KnownContexts { get; init; }
}
