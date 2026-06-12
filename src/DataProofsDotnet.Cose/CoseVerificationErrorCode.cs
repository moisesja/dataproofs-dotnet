namespace DataProofsDotnet.Cose;

/// <summary>
/// Structured failure codes for COSE_Sign1, CWT, and VC-JOSE-COSE verification.
/// Verification APIs return these inside <see cref="CoseVerificationFailure"/> instead of
/// throwing — exceptions are reserved for malformed input handed to decode APIs and for
/// caller misconfiguration.
/// </summary>
public enum CoseVerificationErrorCode
{
    /// <summary>The input is not well-formed CBOR or not a structurally valid COSE_Sign1 / CWT.</summary>
    MalformedMessage,

    /// <summary>The input carries a CBOR tag that is not valid for the requested operation.</summary>
    UnexpectedCborTag,

    /// <summary>
    /// The input is a recognized COSE structure other than COSE_Sign1 (for example COSE_Mac0,
    /// tag 17, or COSE_Encrypt0, tag 16). Only signed COSE_Sign1 structures are supported.
    /// </summary>
    UnsupportedCoseStructure,

    /// <summary>No algorithm (label 1) header parameter is present in the message.</summary>
    MissingAlgorithm,

    /// <summary>The algorithm header is present but outside the supported v1 set (<see cref="CoseAlgorithm"/>).</summary>
    UnsupportedAlgorithm,

    /// <summary>The algorithm header does not match the key type the caller supplied for verification.</summary>
    AlgorithmKeyMismatch,

    /// <summary>The crit (label 2) header lists a label this implementation does not understand (RFC 9052 §3.1).</summary>
    UnknownCriticalHeader,

    /// <summary>The message payload is detached (nil) and no detached payload was supplied.</summary>
    PayloadMissing,

    /// <summary>The cryptographic signature does not verify.</summary>
    InvalidSignature,

    /// <summary>VC-JOSE-COSE: the content type (label 3) protected header is absent or not <c>application/vc</c>.</summary>
    InvalidContentType,

    /// <summary>VC-JOSE-COSE: the typ (label 16, RFC 9596) protected header is absent or not <c>application/vc+cose</c>.</summary>
    InvalidType,

    /// <summary>CWT: the COSE_Sign1 payload is not a well-formed CWT claims set (RFC 8392 §3).</summary>
    MalformedClaims,

    /// <summary>CWT: the exp (4) claim is in the past beyond the configured clock skew.</summary>
    Expired,

    /// <summary>CWT: the nbf (5) claim is in the future beyond the configured clock skew.</summary>
    NotYetValid,
}
