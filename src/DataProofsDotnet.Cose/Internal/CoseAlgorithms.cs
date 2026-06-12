using NetCrypto;

namespace DataProofsDotnet.Cose.Internal;

/// <summary>Algorithm identifier ↔ NetCrypto <see cref="KeyType"/> mapping for the v1 set.</summary>
internal static class CoseAlgorithms
{
    internal static bool TryMap(long algorithmId, out CoseAlgorithm algorithm)
    {
        switch (algorithmId)
        {
            case (long)CoseAlgorithm.EdDsa:
                algorithm = CoseAlgorithm.EdDsa;
                return true;
            case (long)CoseAlgorithm.ES256:
                algorithm = CoseAlgorithm.ES256;
                return true;
            case (long)CoseAlgorithm.ES384:
                algorithm = CoseAlgorithm.ES384;
                return true;
            case (long)CoseAlgorithm.ES256K:
                algorithm = CoseAlgorithm.ES256K;
                return true;
            default:
                algorithm = default;
                return false;
        }
    }

    internal static KeyType GetKeyType(CoseAlgorithm algorithm) => algorithm switch
    {
        CoseAlgorithm.EdDsa => KeyType.Ed25519,
        CoseAlgorithm.ES256 => KeyType.P256,
        CoseAlgorithm.ES384 => KeyType.P384,
        CoseAlgorithm.ES256K => KeyType.Secp256k1,
        _ => throw new CoseException($"COSE algorithm {(long)algorithm} is not in the supported set (EdDSA -8, ES256 -7, ES384 -35, ES256K -47)."),
    };

    /// <summary>Expected signature length in bytes (EdDSA 64; ECDSA fixed-width IEEE P1363 R‖S).</summary>
    internal static int GetSignatureLength(CoseAlgorithm algorithm) => algorithm switch
    {
        CoseAlgorithm.EdDsa => 64,
        CoseAlgorithm.ES256 => 64,
        CoseAlgorithm.ES384 => 96,
        CoseAlgorithm.ES256K => 64,
        _ => throw new CoseException($"COSE algorithm {(long)algorithm} is not in the supported set."),
    };

    /// <summary>
    /// NIST-curve ECDSA algorithms whose NetCrypto signer output is DER and must be transcoded to
    /// IEEE P1363 R‖S (COSE wire format, RFC 9053 §2.1). Ed25519 and secp256k1 signatures are
    /// already 64-byte fixed-width.
    /// </summary>
    internal static bool IsNistEcdsa(CoseAlgorithm algorithm) =>
        algorithm is CoseAlgorithm.ES256 or CoseAlgorithm.ES384;

    /// <summary>Per-curve P1363 field width in bytes (P-256 → 32, P-384 → 48).</summary>
    internal static int GetEcdsaFieldWidth(CoseAlgorithm algorithm) => algorithm switch
    {
        CoseAlgorithm.ES256 => 32,
        CoseAlgorithm.ES384 => 48,
        _ => throw new CoseException($"Algorithm {algorithm} is not a NIST-curve ECDSA algorithm."),
    };

    internal static bool IsDefined(CoseAlgorithm algorithm) =>
        algorithm is CoseAlgorithm.EdDsa or CoseAlgorithm.ES256 or CoseAlgorithm.ES384 or CoseAlgorithm.ES256K;
}
