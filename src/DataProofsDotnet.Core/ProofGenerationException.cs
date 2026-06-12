namespace DataProofsDotnet;

/// <summary>
/// Raised when a proof cannot be created because the proof options, document, signer,
/// or cryptosuite configuration are invalid (the spec's <c>PROOF_GENERATION_ERROR</c>
/// condition). Verification failures are never reported through this exception; they
/// surface as structured results (FR-3).
/// </summary>
public sealed class ProofGenerationException : DataProofsException
{
    /// <summary>Initializes a new instance with a default message.</summary>
    public ProofGenerationException()
    {
    }

    /// <summary>Initializes a new instance with the given message.</summary>
    /// <param name="message">The error message. Must not contain secrets, keys, or payloads.</param>
    public ProofGenerationException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance with the given message and inner exception.</summary>
    /// <param name="message">The error message. Must not contain secrets, keys, or payloads.</param>
    /// <param name="innerException">The underlying cause.</param>
    public ProofGenerationException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }
}
