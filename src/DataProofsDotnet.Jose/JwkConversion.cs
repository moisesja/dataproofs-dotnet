using Microsoft.IdentityModel.Tokens;
using NetCid;
using NetCrypto;
using NetCryptoJwkConverter = NetCrypto.JwkConverter;

namespace DataProofsDotnet.Jose;

/// <summary>
/// Conversions between the JOSE <see cref="Jwk"/> model, the
/// <see cref="Microsoft.IdentityModel.Tokens.JsonWebKey"/> boundary type, NetCrypto raw key
/// representations, and the W3C Multikey (<c>publicKeyMultibase</c>) encoding via NetCid
/// (PRD FR-15).
/// </summary>
/// <remarks>
/// Ported from didcomm-dotnet <c>DidComm.Jose.JwkConversion</c> (PRD §1.4 item 2), rerouted to
/// NetCrypto's <c>JwkConverter</c> (which owns the EC invalid-curve defense per RFC 7518
/// §6.2.2) and extended with the Multikey direction. Off-curve point validation happens
/// automatically inside <see cref="ExtractPublicKey(Jwk)"/> — callers that pass a malformed EC
/// JWK receive a <see cref="System.Security.Cryptography.CryptographicException"/> before any
/// key bytes are returned.
/// </remarks>
public static class JwkConversion
{
    /// <summary>Convert a <see cref="Jwk"/> to the <see cref="JsonWebKey"/> boundary representation.</summary>
    /// <param name="source">The JWK to convert.</param>
    /// <exception cref="MalformedJoseException">When an OKP key's <c>x</c> does not decode to exactly 32 bytes.</exception>
    public static JsonWebKey ToJsonWebKey(Jwk source)
    {
        ArgumentNullException.ThrowIfNull(source);

        // Defense-in-depth for OKP (Ed25519 / X25519): the EC path validates the point is on-curve,
        // but OKP keys import raw bytes straight into the primitive. Reject any 'x' that does not
        // decode to exactly 32 bytes (RFC 8037 §2) before it reaches the crypto layer, so a
        // truncated, oversized, or otherwise malformed attacker-supplied OKP key can't hit the
        // primitive. This is the single chokepoint every public-key import (JWE epk/sender,
        // JWS signer) flows through.
        if (string.Equals(source.Kty, "OKP", StringComparison.Ordinal) && !IsValid32ByteKey(source.X))
            throw new MalformedJoseException("OKP JWK 'x' must decode to exactly 32 bytes (Ed25519/X25519).");

        return new JsonWebKey
        {
            Kty = source.Kty,
            Crv = source.Crv,
            X = source.X,
            Y = source.Y,
            D = source.D,
            Kid = source.Kid,
            Alg = source.Alg,
            Use = source.Use,
        };
    }

    /// <summary>
    /// Extract the (key type, raw public key bytes) pair from a JWK. Delegates to NetCrypto's
    /// <c>JwkConverter.ExtractPublicKey</c> so the invalid-curve defense (RFC 7518 §6.2.2) runs
    /// before any bytes are returned. EC keys come back as compressed SEC1 points — the
    /// canonical NetCrypto encoding, directly usable with <c>DeriveSharedSecret</c> and
    /// <c>Verify</c>.
    /// </summary>
    /// <param name="jwk">The JWK to extract from.</param>
    /// <exception cref="System.Security.Cryptography.CryptographicException">When the JWK contains an off-curve EC point.</exception>
    /// <exception cref="ArgumentException">When the JWK <c>kty</c>/<c>crv</c> combination is unsupported or malformed.</exception>
    /// <exception cref="MalformedJoseException">When an OKP key's <c>x</c> is not exactly 32 bytes.</exception>
    public static (KeyType KeyType, byte[] PublicKey) ExtractPublicKey(Jwk jwk)
        => NetCryptoJwkConverter.ExtractPublicKey(ToJsonWebKey(jwk));

    /// <summary>Build a public-only <see cref="Jwk"/> from a raw public key and key type.</summary>
    /// <param name="keyType">NetCrypto key type.</param>
    /// <param name="publicKey">Raw public key bytes (OKP raw 32; EC compressed or uncompressed SEC1).</param>
    /// <param name="kid">Optional key identifier to carry on the resulting JWK.</param>
    public static Jwk ToPublicJwk(KeyType keyType, byte[] publicKey, string? kid = null)
    {
        var boundary = NetCryptoJwkConverter.ToPublicJwk(keyType, publicKey);
        return new Jwk
        {
            Kty = boundary.Kty,
            Crv = boundary.Crv,
            X = boundary.X,
            Y = boundary.Y,
            Kid = kid,
        };
    }

    /// <summary>Build a private <see cref="Jwk"/> from a NetCrypto <see cref="KeyPair"/>.</summary>
    /// <param name="keyPair">The key pair (private key included).</param>
    /// <param name="kid">Optional key identifier to carry on the resulting JWK.</param>
    public static Jwk ToPrivateJwk(KeyPair keyPair, string? kid = null)
    {
        ArgumentNullException.ThrowIfNull(keyPair);
        var boundary = NetCryptoJwkConverter.ToPrivateJwk(keyPair);
        return new Jwk
        {
            Kty = boundary.Kty,
            Crv = boundary.Crv,
            X = boundary.X,
            Y = boundary.Y,
            D = boundary.D,
            Kid = kid,
        };
    }

    /// <summary>
    /// Encode the public half of <paramref name="jwk"/> as a W3C Multikey
    /// (<c>publicKeyMultibase</c>: base58-btc multibase of multicodec-prefixed raw key bytes)
    /// via NetCid (PRD FR-15).
    /// </summary>
    /// <param name="jwk">A JWK whose public material to encode. Private members are ignored.</param>
    /// <exception cref="MalformedJoseException">When the JWK is malformed or its key type has no multicodec mapping.</exception>
    public static string ToMultikey(Jwk jwk)
    {
        ArgumentNullException.ThrowIfNull(jwk);
        KeyType keyType;
        byte[] raw;
        try
        {
            (keyType, raw) = ExtractPublicKey(jwk);
        }
        catch (ArgumentException ex)
        {
            throw new MalformedJoseException("JWK cannot be converted to Multikey: unsupported or malformed key.", ex);
        }
        return Multikey.Encode(keyType.GetMulticodec(), raw);
    }

    /// <summary>
    /// Decode a W3C Multikey (<c>publicKeyMultibase</c>) string into a public-only
    /// <see cref="Jwk"/> via NetCid (PRD FR-15). EC points are decompressed to JWK
    /// <c>x</c>/<c>y</c> coordinates by NetCrypto.
    /// </summary>
    /// <param name="publicKeyMultibase">The <c>z</c>-prefixed base58-btc Multikey string.</param>
    /// <param name="kid">Optional key identifier to carry on the resulting JWK.</param>
    /// <exception cref="MalformedJoseException">When the value is not a valid Multikey or carries an unsupported key type.</exception>
    public static Jwk FromMultikey(string publicKeyMultibase, string? kid = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(publicKeyMultibase);
        if (!Multikey.TryDecode(publicKeyMultibase, out var codec, out var raw) || raw is null)
            throw new MalformedJoseException("Value is not a valid publicKeyMultibase (Multikey) string.");

        KeyType keyType;
        try
        {
            keyType = KeyTypeExtensions.FromMulticodec(codec);
        }
        catch (ArgumentException ex)
        {
            throw new MalformedJoseException($"Multikey codec 0x{codec:X} has no NetCrypto key-type mapping.", ex);
        }

        return ToPublicJwk(keyType, raw, kid);
    }

    private static bool IsValid32ByteKey(string? x)
    {
        if (string.IsNullOrEmpty(x))
            return false;
        try
        {
            return Base64Url.Decode(x).Length == 32;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
