using NetCrypto;

namespace DataProofsDotnet.Rdfc.Tests.TestSupport;

/// <summary>
/// AC-8 instrument for <c>bbs-2023</c> (issue #44): wraps an <see cref="ICapableKeyStore"/> and
/// records every member invoked through it, as <c>Core.Tests</c>' <c>RecordingKeyStore</c> does for
/// <see cref="IKeyStore"/>. <see cref="TamperSignature"/> lets a test stand in for a store that
/// answers <see cref="SignBbsAsync"/> wrongly, and the tokens each call received are kept.
/// </summary>
internal sealed class RecordingCapableKeyStore : ICapableKeyStore, IDisposable
{
    private readonly ICapableKeyStore _inner;
    private readonly List<string> _calls = [];
    private readonly List<CancellationToken> _tokens = [];

    public RecordingCapableKeyStore(ICapableKeyStore inner) => _inner = inner;

    /// <summary>A store over NetCrypto's in-memory backend that advertises BBS signing.</summary>
    public static RecordingCapableKeyStore WithBbs()
        => new(new CapableInMemoryKeyStore(Fx.KeyGen, Fx.Crypto, new DefaultBbsCryptoProvider(BbsCiphersuite.Bls12381Sha256)));

    /// <summary>The recorded member names, in invocation order; overloads are told apart by a suffix.</summary>
    public IReadOnlyList<string> Calls => _calls;

    /// <summary>The cancellation token each recorded call received, in invocation order.</summary>
    public IReadOnlyList<CancellationToken> Tokens => _tokens;

    /// <summary>The last BBS signing request the store received.</summary>
    public KeyBbsSignRequest? LastBbsRequest { get; private set; }

    /// <summary>Replaces the signature the inner store produced (request, genuine signature → returned).</summary>
    public Func<KeyBbsSignRequest, byte[], byte[]>? TamperSignature { get; set; }

    public void ClearCalls()
    {
        _calls.Clear();
        _tokens.Clear();
    }

    private void Record(string name, CancellationToken ct)
    {
        _calls.Add(name);
        _tokens.Add(ct);
    }

    public KeyStoreNamespaceId NamespaceId => _inner.NamespaceId;

    public Task<KeyStoreCapabilitySet> GetCapabilitiesAsync(CancellationToken ct = default)
    {
        Record(nameof(GetCapabilitiesAsync), ct);
        return _inner.GetCapabilitiesAsync(ct);
    }

    public Task<KeyMutationResult> GenerateAsync(KeyGenerateRequest request, CancellationToken ct = default)
    {
        Record(nameof(GenerateAsync) + "(request)", ct);
        return _inner.GenerateAsync(request, ct);
    }

    public Task<KeyMutationResult> ImportAsync(KeyImportRequest request, CancellationToken ct = default)
    {
        Record(nameof(ImportAsync) + "(request)", ct);
        return _inner.ImportAsync(request, ct);
    }

    public Task<KeyDeleteResult> DeleteAsync(KeyDeleteRequest request, CancellationToken ct = default)
    {
        Record(nameof(DeleteAsync) + "(request)", ct);
        return _inner.DeleteAsync(request, ct);
    }

    public Task<KeyMutationOutcome?> GetMutationOutcomeAsync(KeyMutationKind kind, KeyOperationId operationId, CancellationToken ct = default)
    {
        Record(nameof(GetMutationOutcomeAsync), ct);
        return _inner.GetMutationOutcomeAsync(kind, operationId, ct);
    }

    public Task<StoredKeyInfo?> GetInfoAsync(string alias, KeyInstanceId instanceId, CancellationToken ct = default)
    {
        Record(nameof(GetInfoAsync) + "(alias, instanceId)", ct);
        return _inner.GetInfoAsync(alias, instanceId, ct);
    }

    public Task<byte[]> SignAsync(KeySignRequest request, CancellationToken ct = default)
    {
        Record(nameof(SignAsync) + "(request)", ct);
        return _inner.SignAsync(request, ct);
    }

    public async Task<byte[]> SignBbsAsync(KeyBbsSignRequest request, CancellationToken ct = default)
    {
        Record(nameof(SignBbsAsync), ct);
        LastBbsRequest = request;
        var signature = await _inner.SignBbsAsync(request, ct).ConfigureAwait(false);
        return TamperSignature is { } tamper ? tamper(request, signature) : signature;
    }

    public Task<byte[]> DeriveSharedSecretAsync(KeyAgreementRequest request, CancellationToken ct = default)
    {
        Record(nameof(DeriveSharedSecretAsync) + "(request)", ct);
        return _inner.DeriveSharedSecretAsync(request, ct);
    }

    public Task<StoredKeyInfo> GenerateAsync(string alias, KeyType keyType, CancellationToken ct = default)
    {
        Record(nameof(GenerateAsync), ct);
        return _inner.GenerateAsync(alias, keyType, ct);
    }

    public Task<StoredKeyInfo> ImportAsync(string alias, KeyPair keyPair, CancellationToken ct = default)
    {
        Record(nameof(ImportAsync), ct);
        return _inner.ImportAsync(alias, keyPair, ct);
    }

    public Task<StoredKeyInfo?> GetInfoAsync(string alias, CancellationToken ct = default)
    {
        Record(nameof(GetInfoAsync), ct);
        return _inner.GetInfoAsync(alias, ct);
    }

    public Task<byte[]> SignAsync(string alias, ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        Record(nameof(SignAsync), ct);
        return _inner.SignAsync(alias, data, ct);
    }

    public Task<ISigner> CreateSignerAsync(string alias, CancellationToken ct = default)
    {
        Record(nameof(CreateSignerAsync), ct);
        return _inner.CreateSignerAsync(alias, ct);
    }

    public Task<byte[]> DeriveSharedSecretAsync(string alias, ReadOnlyMemory<byte> peerPublicKey, CancellationToken ct = default)
    {
        Record(nameof(DeriveSharedSecretAsync), ct);
        return _inner.DeriveSharedSecretAsync(alias, peerPublicKey, ct);
    }

    public Task<RecoverableSignature> SignDigestAsync(string alias, ReadOnlyMemory<byte> digest32, CancellationToken ct = default)
    {
        Record(nameof(SignDigestAsync), ct);
        return _inner.SignDigestAsync(alias, digest32, ct);
    }

    public Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default)
    {
        Record(nameof(ListAsync), ct);
        return _inner.ListAsync(ct);
    }

    public Task<bool> DeleteAsync(string alias, CancellationToken ct = default)
    {
        Record(nameof(DeleteAsync), ct);
        return _inner.DeleteAsync(alias, ct);
    }

    public void Dispose() => (_inner as IDisposable)?.Dispose();
}
