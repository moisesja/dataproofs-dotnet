namespace DataProofsDotnet.Cose;

/// <summary>
/// Thrown for malformed CBOR/COSE input handed to a decode API and for caller
/// misconfiguration (for example an algorithm/key-type mismatch at signing time).
/// Verification failures over well-formed input are reported as structured results
/// (<see cref="CoseSign1VerificationResult"/> / <see cref="CwtVerificationResult"/>),
/// never as exceptions.
/// </summary>
/// <remarks>
/// Deliberately self-contained: <c>DataProofsDotnet.Core</c> does not yet ship the FR-23
/// library-base exception. Follow-up: re-root this type on the Core base exception once
/// that hierarchy lands.
/// </remarks>
public sealed class CoseException : Exception
{
    /// <summary>Creates a new <see cref="CoseException"/> with the given message.</summary>
    public CoseException(string message)
        : base(message)
    {
    }

    /// <summary>Creates a new <see cref="CoseException"/> with the given message and inner exception.</summary>
    public CoseException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }
}
