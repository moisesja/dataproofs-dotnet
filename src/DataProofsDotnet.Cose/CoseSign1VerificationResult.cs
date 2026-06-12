namespace DataProofsDotnet.Cose;

/// <summary>
/// Structured outcome of a COSE_Sign1 (or VC-JOSE-COSE) verification: a verified flag plus
/// failure detail. Invalid signatures, headers, and structures yield a result — never an
/// exception. Immutable.
/// </summary>
public sealed class CoseSign1VerificationResult
{
    private CoseSign1VerificationResult(bool verified, CoseVerificationFailure? failure, CoseSign1Message? message)
    {
        Verified = verified;
        Failure = failure;
        Message = message;
    }

    /// <summary>Whether the signature (and, for VC-JOSE-COSE, the required headers) verified.</summary>
    public bool Verified { get; }

    /// <summary>Failure detail when <see cref="Verified"/> is <see langword="false"/>; otherwise <see langword="null"/>.</summary>
    public CoseVerificationFailure? Failure { get; }

    /// <summary>
    /// The decoded message when the input was structurally decodable (also populated for most
    /// failures, e.g. an invalid signature); <see langword="null"/> when decoding itself failed.
    /// </summary>
    public CoseSign1Message? Message { get; }

    internal static CoseSign1VerificationResult Success(CoseSign1Message message) => new(true, null, message);

    internal static CoseSign1VerificationResult Fail(CoseVerificationFailure failure, CoseSign1Message? message = null) =>
        new(false, failure, message);

    internal static CoseSign1VerificationResult Fail(CoseVerificationErrorCode code, string message, CoseSign1Message? decoded = null) =>
        new(false, new CoseVerificationFailure(code, message), decoded);
}
