using NetCrypto;

namespace DataProofsDotnet.Jose.Signing;

/// <summary>
/// One JWS signer: a NetCrypto <see cref="ISigner"/> plus the JOSE metadata (<c>alg</c>,
/// <c>kid</c>) the protected header needs. Signing entry points across this package accept
/// <see cref="JwsSigner"/> — never raw private-key bytes — so an <c>IKeyStore</c>-held key is
/// sufficient for every JWS (PRD AC-8 posture, NFR-3 async signing).
/// </summary>
/// <remarks>
/// <para>
/// The JOSE algorithm is derived from the signer's <see cref="ISigner.KeyType"/>:
/// Ed25519 → <c>EdDSA</c>, secp256k1 → <c>ES256K</c>, P-256 → <c>ES256</c>, P-384 → <c>ES384</c>.
/// P-521 (<c>ES512</c>) and RSA are out of v1 scope (PRD FR-13).
/// </para>
/// <para>
/// <b>Signature-format normalization (PRD FR-13 gotcha):</b> NetCrypto's shipped signers return
/// NIST-curve ECDSA signatures in DER, while JOSE requires fixed-width IEEE P1363 R‖S. For
/// <c>ES256</c>/<c>ES384</c> the output of <see cref="ISigner.SignAsync"/> is transcoded by
/// <see cref="EcdsaSignatureCodec"/> (pure byte parsing, AC-6-clean). Ed25519 and secp256k1
/// signatures are already JOSE-native and pass through untouched.
/// </para>
/// </remarks>
public sealed class JwsSigner
{
    private readonly int _p1363CoordinateLength;

    /// <summary>Create a JWS signer over a NetCrypto signer.</summary>
    /// <param name="signer">The NetCrypto signer holding (or proxying) the private key.</param>
    /// <param name="kid">Optional key identifier written into the JWS headers.</param>
    /// <exception cref="NotSupportedException">When the signer's key type has no v1 JWS algorithm (PRD FR-13).</exception>
    public JwsSigner(ISigner signer, string? kid = null)
    {
        Signer = signer ?? throw new ArgumentNullException(nameof(signer));
        (Algorithm, _p1363CoordinateLength) = signer.KeyType switch
        {
            KeyType.Ed25519 => (JoseAlgorithms.EdDSA, 0),
            KeyType.Secp256k1 => (JoseAlgorithms.ES256K, 0), // NetCrypto secp256k1 already emits compact R‖S
            KeyType.P256 => (JoseAlgorithms.ES256, 32),
            KeyType.P384 => (JoseAlgorithms.ES384, 48),
            _ => throw new NotSupportedException(
                $"Key type '{signer.KeyType}' has no JWS algorithm in v1 (PRD FR-13: EdDSA, ES256K, ES256, ES384)."),
        };
        Kid = kid;
    }

    /// <summary>The underlying NetCrypto signer.</summary>
    public ISigner Signer { get; }

    /// <summary>The JOSE <c>alg</c> this signer produces (derived from the key type).</summary>
    public string Algorithm { get; }

    /// <summary>The key identifier written into the JWS headers; <c>null</c> to omit.</summary>
    public string? Kid { get; }

    /// <summary>Sign the JWS signing input and return the signature in JOSE wire format.</summary>
    /// <param name="signingInput">The ASCII bytes of <c>BASE64URL(header) "." BASE64URL(payload)</c>.</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    internal async Task<byte[]> SignAsync(ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var signature = await Signer.SignAsync(signingInput, cancellationToken).ConfigureAwait(false);
        return _p1363CoordinateLength == 0
            ? signature
            : EcdsaSignatureCodec.EnsureIeeeP1363(signature, _p1363CoordinateLength);
    }
}
