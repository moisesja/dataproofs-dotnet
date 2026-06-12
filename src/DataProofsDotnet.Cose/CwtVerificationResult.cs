namespace DataProofsDotnet.Cose;

/// <summary>
/// Structured outcome of CWT verification: signature verification plus claims validation.
/// Invalid signatures and out-of-window claims yield a result — never an exception. Immutable.
/// </summary>
public sealed class CwtVerificationResult
{
    private CwtVerificationResult(bool verified, CoseVerificationFailure? failure, CwtClaims? claims)
    {
        Verified = verified;
        Failure = failure;
        Claims = claims;
    }

    /// <summary>Whether the signature verified and the claims passed time validation.</summary>
    public bool Verified { get; }

    /// <summary>Failure detail when <see cref="Verified"/> is <see langword="false"/>; otherwise <see langword="null"/>.</summary>
    public CoseVerificationFailure? Failure { get; }

    /// <summary>
    /// The decoded claims set. Populated on success and on time-validation failures
    /// (<see cref="CoseVerificationErrorCode.Expired"/> / <see cref="CoseVerificationErrorCode.NotYetValid"/>,
    /// where the signature has already verified); <see langword="null"/> when the signature or
    /// structure was invalid.
    /// </summary>
    public CwtClaims? Claims { get; }

    internal static CwtVerificationResult Success(CwtClaims claims) => new(true, null, claims);

    internal static CwtVerificationResult Fail(CoseVerificationFailure failure, CwtClaims? claims = null) =>
        new(false, failure, claims);

    internal static CwtVerificationResult Fail(CoseVerificationErrorCode code, string message, CwtClaims? claims = null) =>
        new(false, new CoseVerificationFailure(code, message), claims);
}
