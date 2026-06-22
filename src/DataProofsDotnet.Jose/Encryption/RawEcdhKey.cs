namespace DataProofsDotnet.Jose.Encryption;

/// <summary>
/// The raw-bytes <see cref="IEcdhKey"/> that ships in this package: it wraps an in-memory private
/// scalar <c>d</c> and performs ECDH through the supplied <see cref="JoseCryptoProvider"/>. Its
/// <see cref="DeriveAsync"/> completes synchronously and produces a shared secret byte-for-byte
/// identical to the existing sync key-agreement path, so the conformance vectors are unchanged.
/// </summary>
/// <remarks>
/// Use this when the private key material is available in process. For a private key that must never
/// leave a secure boundary (HSM, KMS, keychain), implement <see cref="IEcdhKey"/> over that backing
/// instead — this package never needs the scalar, only the derived <c>Z</c>. The constructor takes a
/// defensive copy of the private key; the copy lives for the object's lifetime.
/// </remarks>
public sealed class RawEcdhKey : IEcdhKey
{
    private readonly byte[] _privateKey;
    private readonly JoseCryptoProvider _cryptoProvider;

    /// <summary>Wrap a raw private key for ECDH on <paramref name="crv"/>.</summary>
    /// <param name="crv">JWK <c>crv</c> (<c>X25519</c>, <c>P-256</c>, <c>P-384</c>, or <c>P-521</c>).</param>
    /// <param name="privateKey">Raw private-key bytes (scalar) for <paramref name="crv"/>; copied internally.</param>
    /// <param name="cryptoProvider">The provider performing the raw ECDH.</param>
    public RawEcdhKey(string crv, ReadOnlyMemory<byte> privateKey, JoseCryptoProvider cryptoProvider)
    {
        ArgumentException.ThrowIfNullOrEmpty(crv);
        ArgumentNullException.ThrowIfNull(cryptoProvider);
        Crv = crv;
        _privateKey = privateKey.ToArray();
        _cryptoProvider = cryptoProvider;
    }

    /// <inheritdoc />
    public string Crv { get; }

    /// <inheritdoc />
    public ValueTask<byte[]> DeriveAsync(ReadOnlyMemory<byte> peerPublicKey, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        return new ValueTask<byte[]>(_cryptoProvider.DeriveSharedSecret(Crv, _privateKey, peerPublicKey.Span));
    }
}
