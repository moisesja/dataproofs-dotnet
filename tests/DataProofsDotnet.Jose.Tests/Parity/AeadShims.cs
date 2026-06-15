using NetCrypto;

namespace DataProofsDotnet.Jose.Tests.Crypto.Aead;

// Parity shims (rename-adapted from the didcomm-dotnet port): didcomm-dotnet implemented IAead instance classes
// locally; dataproofs deletes them per AC-6 (every AEAD is a NetCrypto static). These shims
// preserve the porting source's instance call shape — (key, iv, aad, plaintext) order and the
// Name/KeySizeBytes/IvSizeBytes/TagSizeBytes metadata — while delegating every cryptographic
// operation to the NetCrypto cipher statics, so the ported tests keep their assertion content
// byte-for-byte. Metadata derives from the same KeyTypeMapper the JWE layer dispatches on.

internal sealed class AesCbcHmacSha512
{
    public string Name => JoseAlgorithms.A256CbcHs512;
    public int KeySizeBytes => Jose.KeyTypeMapper.ContentEncryptionKeySizeBytes(Name);
    public int IvSizeBytes => Jose.KeyTypeMapper.IvSizeBytes(Name);
    public int TagSizeBytes => 32;

    public (byte[] Ciphertext, byte[] Tag) Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext)
        => AesCbcHmacCipher.Encrypt(key, iv, plaintext, aad);

    public byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag)
        => AesCbcHmacCipher.Decrypt(key, iv, ciphertext, tag, aad);
}

internal sealed class AesGcmAead
{
    public string Name => JoseAlgorithms.A256Gcm;
    public int KeySizeBytes => Jose.KeyTypeMapper.ContentEncryptionKeySizeBytes(Name);
    public int IvSizeBytes => Jose.KeyTypeMapper.IvSizeBytes(Name);
    public int TagSizeBytes => 16;

    public (byte[] Ciphertext, byte[] Tag) Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext)
        => AesGcmCipher.Encrypt(key, iv, plaintext, aad);

    public byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag)
        => AesGcmCipher.Decrypt(key, iv, ciphertext, tag, aad);
}

internal sealed class XChaCha20Poly1305Aead
{
    public string Name => JoseAlgorithms.XC20P;
    public int KeySizeBytes => Jose.KeyTypeMapper.ContentEncryptionKeySizeBytes(Name);
    public int IvSizeBytes => Jose.KeyTypeMapper.IvSizeBytes(Name);
    public int TagSizeBytes => 16;

    public (byte[] Ciphertext, byte[] Tag) Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> plaintext)
        => XChaCha20Poly1305Cipher.Encrypt(key, iv, plaintext, aad);

    public byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag)
        => XChaCha20Poly1305Cipher.Decrypt(key, iv, ciphertext, tag, aad);
}
