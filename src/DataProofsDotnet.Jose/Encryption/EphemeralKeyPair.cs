using System.Security.Cryptography;
using NetCrypto;

namespace DataProofsDotnet.Jose.Encryption;

/// <summary>
/// A freshly-generated per-envelope ephemeral key pair for ECDH. JWE protected headers carry
/// the public half as <c>epk</c>; the private half is held in memory for the duration of the
/// encrypt call, then released. Wraps NetCrypto's <see cref="DefaultKeyGenerator"/> so this
/// layer does not duplicate per-curve generation logic (NFR-5: ephemeral keys come from
/// NetCrypto key generation). Ported from didcomm-dotnet
/// <c>DidComm.Crypto.KeyAgreement.EphemeralKeyPair</c> (PRD §1.4 item 2).
/// </summary>
internal sealed class EphemeralKeyPair
{
    private static readonly IKeyGenerator _generator = new DefaultKeyGenerator();

    /// <summary>The JOSE curve this pair was generated on.</summary>
    public string Curve { get; }

    /// <summary>Raw public-key bytes in the NetCrypto canonical shape (OKP raw 32 / EC compressed SEC1).</summary>
    public byte[] PublicKey { get; }

    /// <summary>Raw private-key bytes (scalar). Caller is responsible for releasing after use.</summary>
    public byte[] PrivateKey { get; }

    private EphemeralKeyPair(string curve, byte[] publicKey, byte[] privateKey)
    {
        Curve = curve;
        PublicKey = publicKey;
        PrivateKey = privateKey;
    }

    /// <summary>Generate a new key pair for the requested JOSE curve.</summary>
    /// <param name="crv">JWK <c>crv</c> value — one of <c>X25519</c>, <c>P-256</c>, <c>P-384</c>, <c>P-521</c>.</param>
    public static EphemeralKeyPair Generate(string crv)
    {
        ArgumentException.ThrowIfNullOrEmpty(crv);
        var keyType = KeyTypeMapper.FromCurveForKeyAgreement(crv);
        var pair = _generator.Generate(keyType);
        return new EphemeralKeyPair(crv, pair.PublicKey, pair.PrivateKey);
    }

    /// <summary>
    /// Build a JWK <c>epk</c> object for the public half of this pair. Used to populate the JWE
    /// protected header at encrypt time.
    /// </summary>
    public Jwk ToPublicEpkJwk()
        => JwkConversion.ToPublicJwk(KeyTypeMapper.FromCurveForKeyAgreement(Curve), PublicKey);

    /// <summary>Release private-key material as best as the platform allows.</summary>
    public void Clear() => CryptographicOperations.ZeroMemory(PrivateKey);
}
