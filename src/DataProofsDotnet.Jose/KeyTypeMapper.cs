using NetCrypto;

namespace DataProofsDotnet.Jose;

/// <summary>
/// Routing between JOSE-world identifiers (JWK <c>crv</c> / <c>kty</c>, JWE <c>alg</c>/<c>enc</c>)
/// and the NetCrypto <see cref="KeyType"/> enum. One source of truth so the JWE/JWS builders
/// never hard-code curve-to-keytype matches. Ported from didcomm-dotnet
/// <c>DidComm.Crypto.KeyAgreement.KeyTypeMapper</c> (PRD §1.4 item 2), rerouted to NetCrypto.
/// </summary>
internal static class KeyTypeMapper
{
    /// <summary>
    /// Map a JWK <c>crv</c> value to the <see cref="KeyType"/> used by NetCrypto's ECDH
    /// primitive. Throws when the curve is not supported for key agreement.
    /// </summary>
    /// <param name="crv">JWK <c>crv</c> value.</param>
    /// <exception cref="NotSupportedException">When <paramref name="crv"/> is not a supported key-agreement curve.</exception>
    public static KeyType FromCurveForKeyAgreement(string crv) => crv switch
    {
        JoseAlgorithms.CrvX25519 => KeyType.X25519,
        JoseAlgorithms.CrvP256 => KeyType.P256,
        JoseAlgorithms.CrvP384 => KeyType.P384,
        JoseAlgorithms.CrvP521 => KeyType.P521,
        _ => throw new NotSupportedException($"Curve '{crv}' is not supported for key agreement."),
    };

    /// <summary>Map a <see cref="KeyType"/> to its JWK <c>crv</c> value.</summary>
    /// <param name="keyType">The NetCrypto key type.</param>
    public static string ToCurve(KeyType keyType) => keyType switch
    {
        KeyType.Ed25519 => JoseAlgorithms.CrvEd25519,
        KeyType.X25519 => JoseAlgorithms.CrvX25519,
        KeyType.P256 => JoseAlgorithms.CrvP256,
        KeyType.P384 => JoseAlgorithms.CrvP384,
        KeyType.P521 => JoseAlgorithms.CrvP521,
        KeyType.Secp256k1 => JoseAlgorithms.CrvSecp256k1,
        _ => throw new NotSupportedException($"KeyType '{keyType}' has no JWK curve mapping in this layer."),
    };

    /// <summary>Map a JWK <c>crv</c> to the <see cref="KeyType"/> used for signing (includes secp256k1 and Ed25519).</summary>
    /// <param name="crv">JWK <c>crv</c> value.</param>
    public static KeyType FromCurveForSigning(string crv) => crv switch
    {
        JoseAlgorithms.CrvEd25519 => KeyType.Ed25519,
        JoseAlgorithms.CrvP256 => KeyType.P256,
        JoseAlgorithms.CrvP384 => KeyType.P384,
        JoseAlgorithms.CrvP521 => KeyType.P521,
        JoseAlgorithms.CrvSecp256k1 => KeyType.Secp256k1,
        _ => throw new NotSupportedException($"Curve '{crv}' is not supported for signing."),
    };

    /// <summary>The JOSE signing algorithm matched to a JWK curve.</summary>
    /// <param name="crv">JWK <c>crv</c> value (Ed25519, P-256, P-384, P-521, secp256k1).</param>
    public static string ToJwsAlgorithm(string crv) => crv switch
    {
        JoseAlgorithms.CrvEd25519 => JoseAlgorithms.EdDSA,
        JoseAlgorithms.CrvP256 => JoseAlgorithms.ES256,
        JoseAlgorithms.CrvP384 => JoseAlgorithms.ES384,
        JoseAlgorithms.CrvP521 => JoseAlgorithms.ES512,
        JoseAlgorithms.CrvSecp256k1 => JoseAlgorithms.ES256K,
        _ => throw new NotSupportedException($"Curve '{crv}' has no JWS algorithm mapping."),
    };

    /// <summary>The CEK length in bytes for a given content-encryption algorithm.</summary>
    /// <param name="contentEncryption">JWE <c>enc</c> value.</param>
    public static int ContentEncryptionKeySizeBytes(string contentEncryption) => contentEncryption switch
    {
        JoseAlgorithms.A256CbcHs512 => 64, // 32 MAC + 32 ENC (RFC 7518 §5.2.5)
        JoseAlgorithms.A256Gcm => 32,
        JoseAlgorithms.XC20P => 32,
        _ => throw new NotSupportedException($"Content-encryption algorithm '{contentEncryption}' is not supported."),
    };

    /// <summary>The IV / nonce length in bytes for a given content-encryption algorithm.</summary>
    /// <param name="contentEncryption">JWE <c>enc</c> value.</param>
    public static int IvSizeBytes(string contentEncryption) => contentEncryption switch
    {
        JoseAlgorithms.A256CbcHs512 => 16,
        JoseAlgorithms.A256Gcm => 12,
        JoseAlgorithms.XC20P => 24,
        _ => throw new NotSupportedException($"Content-encryption algorithm '{contentEncryption}' is not supported."),
    };
}
