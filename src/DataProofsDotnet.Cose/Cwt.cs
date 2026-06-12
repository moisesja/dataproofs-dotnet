using DataProofsDotnet.Cose.Internal;
using NetCrypto;

namespace DataProofsDotnet.Cose;

/// <summary>
/// CBOR Web Tokens per RFC 8392 (FR-19): a CWT claims set carried as the payload of a signed
/// COSE_Sign1. Handles the CWT CBOR tag (61) and the COSE_Sign1 tag (18) on both emit and
/// accept. MACed (COSE_Mac0) and encrypted (COSE_Encrypt0) CWTs are out of v1 scope and are
/// rejected with <see cref="CoseVerificationErrorCode.UnsupportedCoseStructure"/>.
/// Stateless and thread-safe.
/// </summary>
public static class Cwt
{
    /// <summary>
    /// Encodes <paramref name="claims"/> as a CWT claims set and signs it as a COSE_Sign1.
    /// Emits <c>18(…)</c>, or <c>61(18(…))</c> when <see cref="CwtSignOptions.IncludeCwtTag"/> is set.
    /// </summary>
    /// <exception cref="CoseException">Misconfiguration (algorithm/key-type mismatch).</exception>
    public static async Task<byte[]> SignAsync(
        CwtClaims claims,
        ISigner signer,
        CwtSignOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(options);
        byte[] claimsSet = CwtClaimsCodec.Encode(claims);
        var signOptions = new CoseSign1SignOptions
        {
            Algorithm = options.Algorithm,
            KeyId = options.KeyId,
        };
        byte[] coseSign1 = await CoseSign1.SignAsync(claimsSet, signer, signOptions, cancellationToken).ConfigureAwait(false);
        return options.IncludeCwtTag ? CoseSign1Codec.WrapInCwtTag(coseSign1) : coseSign1;
    }

    /// <summary>
    /// Verifies a signed CWT: accepts <c>61(18(…))</c>, <c>18(…)</c>, or an untagged COSE_Sign1;
    /// verifies the signature against the raw public key; then validates exp/nbf against
    /// <see cref="CwtValidationOptions.ValidationTime"/> with the configured clock skew.
    /// All invalid inputs yield a structured result, never an exception.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The configured clock skew is negative (misconfiguration).</exception>
    public static CwtVerificationResult Verify(
        ReadOnlyMemory<byte> encodedCwt,
        KeyType keyType,
        ReadOnlyMemory<byte> publicKey,
        CwtValidationOptions? options = null)
    {
        TimeSpan clockSkew = options?.ClockSkew ?? TimeSpan.Zero;
        if (clockSkew < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "ClockSkew must not be negative.");
        }

        if (!CoseSign1Codec.TryDecode(encodedCwt, CoseTagAcceptance.Cwt, out CoseSign1Message? message, out CoseVerificationFailure? failure))
        {
            return CwtVerificationResult.Fail(failure);
        }

        CoseSign1VerificationResult signatureResult = CoseSign1.VerifyCore(message, keyType, publicKey, externalData: default, detachedPayload: null);
        if (!signatureResult.Verified)
        {
            return CwtVerificationResult.Fail(signatureResult.Failure!);
        }

        if (!CwtClaimsCodec.TryDecode(message.PayloadBytes!, out CwtClaims? claims, out string? claimsError))
        {
            return CwtVerificationResult.Fail(CoseVerificationErrorCode.MalformedClaims, claimsError);
        }

        // RFC 8392 §3.1.4 / RFC 7519 §4.1.4: the validation time MUST be *before* exp —
        // a token is already invalid at exactly exp. nbf (§3.1.5) is inclusive: valid at exactly nbf.
        DateTimeOffset validationTime = options?.ValidationTime ?? DateTimeOffset.UtcNow;
        if (claims.ExpirationTime is { } exp && validationTime >= exp + clockSkew)
        {
            return CwtVerificationResult.Fail(
                CoseVerificationErrorCode.Expired,
                $"The token expired at {exp:O} (validation time {validationTime:O}, clock skew {clockSkew}).",
                claims);
        }

        if (claims.NotBefore is { } nbf && validationTime < nbf - clockSkew)
        {
            return CwtVerificationResult.Fail(
                CoseVerificationErrorCode.NotYetValid,
                $"The token is not valid before {nbf:O} (validation time {validationTime:O}, clock skew {clockSkew}).",
                claims);
        }

        return CwtVerificationResult.Success(claims);
    }

    /// <summary>
    /// Decodes a bare CWT claims set (the CBOR map of RFC 8392 §3) without any signature
    /// processing — e.g. the RFC 8392 Appendix A.1 example.
    /// </summary>
    /// <exception cref="CoseException">The input is not a well-formed CWT claims set.</exception>
    public static CwtClaims DecodeClaims(ReadOnlyMemory<byte> encodedClaimsSet)
    {
        if (!CwtClaimsCodec.TryDecode(encodedClaimsSet, out CwtClaims? claims, out string? error))
        {
            throw new CoseException(error);
        }

        return claims;
    }
}
