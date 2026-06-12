namespace DataProofsDotnet;

/// <summary>
/// Base exception for the DataProofsDotnet library family (FR-23).
/// </summary>
/// <remarks>
/// Exceptions are reserved for malformed inputs and misconfiguration. Verification of
/// invalid proofs never throws; it returns structured results (FR-3). Exception messages
/// never contain secrets, key material, or document payloads.
/// </remarks>
public class DataProofsException : Exception
{
    /// <summary>Initializes a new instance with a default message.</summary>
    public DataProofsException()
    {
    }

    /// <summary>Initializes a new instance with the given message.</summary>
    /// <param name="message">The error message. Must not contain secrets, keys, or payloads.</param>
    public DataProofsException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance with the given message and inner exception.</summary>
    /// <param name="message">The error message. Must not contain secrets, keys, or payloads.</param>
    /// <param name="innerException">The underlying cause.</param>
    public DataProofsException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }
}
