namespace DataProofsDotnet.Cose;

/// <summary>
/// Failure detail attached to a non-verified <see cref="CoseSign1VerificationResult"/> or
/// <see cref="CwtVerificationResult"/>: a stable <see cref="Code"/> plus a human-readable
/// <see cref="Message"/>. Immutable.
/// </summary>
public sealed class CoseVerificationFailure
{
    internal CoseVerificationFailure(CoseVerificationErrorCode code, string message)
    {
        Code = code;
        Message = message;
    }

    /// <summary>The stable, documented failure code.</summary>
    public CoseVerificationErrorCode Code { get; }

    /// <summary>A human-readable description of the failure. Never contains key material or payload bytes.</summary>
    public string Message { get; }
}
