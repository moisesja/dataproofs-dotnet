using Microsoft.IdentityModel.Tokens;
using NetCid;
using NetCrypto;

namespace DataProofsDotnet;

/// <summary>
/// Public verification key material (FR-8). Accepts the two key envelopes this library
/// supports — W3C Multikey (<c>publicKeyMultibase</c>) and JWK — and normalizes them to
/// the raw key representation NetCrypto providers consume.
/// </summary>
/// <remarks>
/// Byte conventions match NetCrypto/NetCid: raw 32 bytes for Ed25519/X25519, SEC1
/// compressed points for the NIST and secp256k1 curves (33/49/67 bytes), and compressed
/// G1/G2 points for BLS12-381. Instances are immutable and thread-safe.
/// </remarks>
public sealed class PublicKeyMaterial
{
    private readonly byte[] _keyBytes;

    private PublicKeyMaterial(KeyType keyType, byte[] keyBytes)
    {
        KeyType = keyType;
        _keyBytes = keyBytes;
    }

    /// <summary>The NetCrypto key type of this key.</summary>
    public KeyType KeyType { get; }

    /// <summary>The raw public key bytes in the canonical NetCrypto encoding.</summary>
    public ReadOnlyMemory<byte> KeyBytes => _keyBytes;

    /// <summary>
    /// Creates key material from raw public key bytes in the canonical encoding for
    /// <paramref name="keyType"/>.
    /// </summary>
    /// <exception cref="ArgumentException">The key length is invalid for the key type.</exception>
    public static PublicKeyMaterial FromRaw(KeyType keyType, ReadOnlySpan<byte> keyBytes)
    {
        if (!keyType.IsValidKeyLength(keyBytes.Length))
        {
            throw new ArgumentException(
                $"Invalid public key length {keyBytes.Length} for key type {keyType}.",
                nameof(keyBytes));
        }

        return new PublicKeyMaterial(keyType, keyBytes.ToArray());
    }

    /// <summary>
    /// Creates key material from a W3C Multikey <c>publicKeyMultibase</c> string
    /// (base58-btc multibase of a multicodec-prefixed raw key), decoded via NetCid.
    /// </summary>
    /// <exception cref="ArgumentException">The value is not a valid Multikey.</exception>
    public static PublicKeyMaterial FromMultikey(string publicKeyMultibase)
    {
        ArgumentException.ThrowIfNullOrEmpty(publicKeyMultibase);

        if (!Multikey.TryDecode(publicKeyMultibase, out var codec, out var rawKey) || rawKey is null)
        {
            throw new ArgumentException("The value is not a valid publicKeyMultibase Multikey.",
                nameof(publicKeyMultibase));
        }

        KeyType keyType;
        try
        {
            keyType = KeyTypeExtensions.FromMulticodec(codec);
        }
        catch (ArgumentException ex)
        {
            throw new ArgumentException("The Multikey uses an unsupported key codec.",
                nameof(publicKeyMultibase), ex);
        }

        return new PublicKeyMaterial(keyType, rawKey);
    }

    /// <summary>
    /// Creates key material from a public <see cref="JsonWebKey"/> (the single
    /// Microsoft.IdentityModel.Tokens type admitted by this library's API surface).
    /// EC coordinates are validated on-curve and normalized to compressed SEC1 form.
    /// </summary>
    /// <exception cref="ArgumentException">The JWK is malformed or unsupported.</exception>
    public static PublicKeyMaterial FromJsonWebKey(JsonWebKey publicKeyJwk)
    {
        ArgumentNullException.ThrowIfNull(publicKeyJwk);

        var (keyType, publicKey) = JwkConverter.ExtractPublicKey(publicKeyJwk);
        return new PublicKeyMaterial(keyType, publicKey);
    }

    /// <summary>Encodes this key as a W3C Multikey <c>publicKeyMultibase</c> string.</summary>
    public string ToMultikey() => Multikey.Encode(KeyType.GetMulticodec(), _keyBytes);

    /// <summary>Converts this key to a public <see cref="JsonWebKey"/>.</summary>
    public JsonWebKey ToJsonWebKey() => JwkConverter.ToPublicJwk(KeyType, _keyBytes);
}
