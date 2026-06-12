namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// Problem-detail codes aligned with the processing errors defined by VC Data Integrity
/// 1.0 (FR-3). Verification failures carry these codes in structured results; they are
/// never thrown.
/// </summary>
public static class ProofProblemCodes
{
    /// <summary>A proof could not be generated (surfaced via <see cref="ProofGenerationException"/>).</summary>
    public const string ProofGenerationError = "PROOF_GENERATION_ERROR";

    /// <summary>A proof failed verification (bad signature, malformed proof, mismatched purpose, expiry, ...).</summary>
    public const string ProofVerificationError = "PROOF_VERIFICATION_ERROR";

    /// <summary>The document or proof configuration could not be transformed (canonicalized).</summary>
    public const string ProofTransformationError = "PROOF_TRANSFORMATION_ERROR";

    /// <summary>The proof's <c>domain</c> did not match the expected domain.</summary>
    public const string InvalidDomainError = "INVALID_DOMAIN_ERROR";

    /// <summary>The proof's <c>challenge</c> did not match the expected challenge.</summary>
    public const string InvalidChallengeError = "INVALID_CHALLENGE_ERROR";

    /// <summary>
    /// The verification method could not be resolved, is not controlled by its declared
    /// controller, or is not authorized (listed under the verification relationship
    /// matching the proof's <c>proofPurpose</c>) by the controller document. Distinct
    /// from a <c>proofPurpose</c>-field mismatch, which is
    /// <see cref="ProofVerificationError"/>.
    /// </summary>
    public const string InvalidVerificationMethod = "INVALID_VERIFICATION_METHOD";
}
