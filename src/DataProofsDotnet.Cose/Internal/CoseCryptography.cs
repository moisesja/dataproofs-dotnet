using NetCrypto;

namespace DataProofsDotnet.Cose.Internal;

/// <summary>
/// The single signature-verification choke point. All cryptography routes through NetCrypto
/// (PRD §2.2): ECDSA verification always uses the <see cref="EcdsaSignatureFormat.IeeeP1363"/>
/// overload because COSE signatures are fixed-width R‖S (RFC 9053 §2.1); non-NIST key types
/// ignore the format parameter.
/// </summary>
internal static class CoseCryptography
{
    private static readonly DefaultCryptoProvider Provider = new();

    internal static bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) =>
        Provider.Verify(keyType, publicKey, data, signature, EcdsaSignatureFormat.IeeeP1363);
}
