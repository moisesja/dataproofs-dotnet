namespace DataProofsDotnet.Jose.Jwt;

/// <summary>
/// Structured outcome of <see cref="JwtHandler.Verify"/>. Invalid tokens produce a result with
/// <see cref="IsValid"/> <c>false</c> and the documented error codes — never an unhandled
/// exception (PRD AC-3 negative-path convention).
/// </summary>
public sealed class JwtVerificationResult
{
    private JwtVerificationResult(bool isValid, JwtClaims? claims, string? signatureAlgorithm, string? signerKid, IReadOnlyList<string> errors)
    {
        IsValid = isValid;
        Claims = claims;
        SignatureAlgorithm = signatureAlgorithm;
        SignerKid = signerKid;
        Errors = errors;
    }

    /// <summary>True when the signature verified and every validation check passed.</summary>
    public bool IsValid { get; }

    /// <summary>The parsed claims set; present whenever the payload parsed, even on validation failure.</summary>
    public JwtClaims? Claims { get; }

    /// <summary>JOSE <c>alg</c> of the verified signature, when signature verification succeeded.</summary>
    public string? SignatureAlgorithm { get; }

    /// <summary>The verified signer key identifier, when signature verification succeeded.</summary>
    public string? SignerKid { get; }

    /// <summary>
    /// Error descriptions for a failed verification. Each begins with one of the stable codes:
    /// <c>MALFORMED</c>, <c>SIGNATURE_INVALID</c>, <c>ALGORITHM_NOT_ALLOWED</c>,
    /// <c>EXPIRED</c>, <c>MISSING_EXPIRATION</c>, <c>NOT_YET_VALID</c>, <c>ISSUED_IN_FUTURE</c>,
    /// <c>ISSUER_MISMATCH</c>, <c>AUDIENCE_MISMATCH</c>, <c>SUBJECT_MISMATCH</c>.
    /// </summary>
    public IReadOnlyList<string> Errors { get; }

    internal static JwtVerificationResult Success(JwtClaims claims, string signatureAlgorithm, string signerKid)
        => new(true, claims, signatureAlgorithm, signerKid, []);

    internal static JwtVerificationResult Failure(IReadOnlyList<string> errors, JwtClaims? claims = null, string? signatureAlgorithm = null, string? signerKid = null)
        => new(false, claims, signatureAlgorithm, signerKid, errors);
}
