using System.Security.Cryptography;
using NetCrypto;

namespace DataProofsDotnet.Jose;

/// <summary>
/// Default <see cref="IJoseCryptoProvider"/>. Every primitive routes through NetCrypto
/// (PRD §2.2: crypto arrives only through NetCrypto): sign/verify and raw ECDH via
/// <see cref="NetCrypto.ICryptoProvider"/>, AEADs via the NetCrypto cipher statics
/// (<c>AesCbcHmacCipher</c>, <c>AesGcmCipher</c>, <c>XChaCha20Poly1305Cipher</c>), and key wrap
/// via <c>NetCrypto.AesKeyWrap</c>.
/// </summary>
/// <remarks>
/// <para>
/// Ported from didcomm-dotnet <c>DidComm.Crypto.DefaultCryptoProvider</c> (PRD §1.4 item 2).
/// Thread-safe — the underlying primitives are stateless (NFR-4). A single
/// <see cref="JoseCryptoProvider"/> is a safe singleton across all build/parse pipelines.
/// </para>
/// <para>
/// <b>Signature-format note (PRD FR-13):</b> NetCrypto's default <c>Sign</c> returns NIST-curve
/// ECDSA in DER; JOSE requires IEEE P1363 (fixed-width R‖S), so ES256/ES384 dispatch through
/// the <see cref="EcdsaSignatureFormat.IeeeP1363"/> overload. secp256k1 natively returns
/// 64-byte compact R‖S and Ed25519 is JOSE-native, so the format argument is ignored for those.
/// </para>
/// </remarks>
public sealed class JoseCryptoProvider : IJoseCryptoProvider
{
    private readonly NetCrypto.ICryptoProvider _netCrypto;

    /// <summary>Create a provider over a fresh NetCrypto <see cref="DefaultCryptoProvider"/>.</summary>
    public JoseCryptoProvider()
        : this(new DefaultCryptoProvider()) { }

    /// <summary>Create a provider over a caller-supplied NetCrypto crypto provider.</summary>
    /// <param name="netCryptoProvider">The NetCrypto provider supplying sign/verify/ECDH.</param>
    public JoseCryptoProvider(NetCrypto.ICryptoProvider netCryptoProvider)
    {
        _netCrypto = netCryptoProvider ?? throw new ArgumentNullException(nameof(netCryptoProvider));
    }

    /// <inheritdoc />
    public bool Verify(string joseAlg, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        var (keyType, format) = MapSigningAlgorithm(joseAlg);
        return _netCrypto.Verify(keyType, publicKey, data, signature, format);
    }

    /// <inheritdoc />
    public byte[] DeriveSharedSecret(string crv, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        var keyType = KeyTypeMapper.FromCurveForKeyAgreement(crv);
        return _netCrypto.DeriveSharedSecret(keyType, privateKey, publicKey);
    }

    /// <inheritdoc />
    public (byte[] Ciphertext, byte[] Tag) AeadEncrypt(
        string enc,
        ReadOnlySpan<byte> cek,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> plaintext)
        => enc switch
        {
            // NetCrypto cipher statics take (key, iv/nonce, plaintext, associatedData).
            JoseAlgorithms.A256CbcHs512 => AesCbcHmacCipher.Encrypt(cek, iv, plaintext, aad),
            JoseAlgorithms.A256Gcm => AesGcmCipher.Encrypt(cek, iv, plaintext, aad),
            JoseAlgorithms.XC20P => XChaCha20Poly1305Cipher.Encrypt(cek, iv, plaintext, aad),
            _ => throw new NotSupportedException($"Content-encryption algorithm '{enc}' is not supported."),
        };

    /// <inheritdoc />
    public byte[] AeadDecrypt(
        string enc,
        ReadOnlySpan<byte> cek,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag)
        => enc switch
        {
            JoseAlgorithms.A256CbcHs512 => AesCbcHmacCipher.Decrypt(cek, iv, ciphertext, tag, aad),
            JoseAlgorithms.A256Gcm => AesGcmCipher.Decrypt(cek, iv, ciphertext, tag, aad),
            JoseAlgorithms.XC20P => XChaCha20Poly1305Cipher.Decrypt(cek, iv, ciphertext, tag, aad),
            _ => throw new NotSupportedException($"Content-encryption algorithm '{enc}' is not supported."),
        };

    /// <inheritdoc />
    public byte[] KeyWrap(string alg, ReadOnlySpan<byte> kek, ReadOnlySpan<byte> cek)
    {
        if (alg != JoseAlgorithms.A256Kw)
            throw new NotSupportedException($"Key-wrap algorithm '{alg}' is not supported. A256KW is the only supported value.");
        return AesKeyWrap.Wrap(kek, cek);
    }

    /// <inheritdoc />
    public byte[] KeyUnwrap(string alg, ReadOnlySpan<byte> kek, ReadOnlySpan<byte> wrapped)
    {
        if (alg != JoseAlgorithms.A256Kw)
            throw new NotSupportedException($"Key-wrap algorithm '{alg}' is not supported. A256KW is the only supported value.");
        return AesKeyWrap.Unwrap(kek, wrapped);
    }

    /// <inheritdoc />
    /// <remarks>
    /// NetCrypto exposes no public randomness API (verified against its PublicAPI surface,
    /// tasks/research/netcrypto-api.md §9), so this routes to the platform CSPRNG access point
    /// <see cref="RandomNumberGenerator.Fill(Span{byte})"/> — a randomness source, not a keyed
    /// or algorithmic primitive, in the same allowlist category as
    /// <c>CryptographicOperations.FixedTimeEquals</c> (NFR-6). Flagged for the AC-6
    /// banned-symbol allowlist; if NetCrypto grows a SecureRandom API, reroute here.
    /// </remarks>
    public void Fill(Span<byte> destination)
        => RandomNumberGenerator.Fill(destination);

    /// <summary>Exposes the underlying NetCrypto provider so the KDF wrappers can reuse it.</summary>
    internal NetCrypto.ICryptoProvider UnderlyingProvider => _netCrypto;

    private static (KeyType KeyType, EcdsaSignatureFormat Format) MapSigningAlgorithm(string joseAlg) => joseAlg switch
    {
        JoseAlgorithms.EdDSA => (KeyType.Ed25519, EcdsaSignatureFormat.Der), // format ignored for Ed25519
        JoseAlgorithms.ES256 => (KeyType.P256, EcdsaSignatureFormat.IeeeP1363),
        JoseAlgorithms.ES384 => (KeyType.P384, EcdsaSignatureFormat.IeeeP1363),
        JoseAlgorithms.ES256K => (KeyType.Secp256k1, EcdsaSignatureFormat.IeeeP1363), // ignored; NetCrypto secp256k1 already returns R‖S
        // ES512 (P-521) is implemented in NetCrypto but out of v1 scope (PRD FR-13) — rejected here.
        _ => throw new NotSupportedException($"Signing algorithm '{joseAlg}' is not supported."),
    };
}
