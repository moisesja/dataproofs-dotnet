using NetCrypto;

namespace DataProofsDotnet.Core.Tests.TestSupport;

/// <summary>
/// AC-8 instrument: wraps NetCrypto's <see cref="InMemoryKeyStore"/> and records every
/// <see cref="IKeyStore"/> member invoked through it. <see cref="CreateSignerAsync"/>
/// returns a <see cref="KeyStoreSigner"/> bound to THIS wrapper, so the signer's
/// signing calls are recorded too.
/// </summary>
internal sealed class RecordingKeyStore : IKeyStore
{
    private readonly IKeyStore _inner;
    private readonly List<string> _calls = [];

    public RecordingKeyStore(IKeyStore inner) => _inner = inner;

    /// <summary>The recorded member names, in invocation order.</summary>
    public IReadOnlyList<string> Calls => _calls;

    public void ClearCalls() => _calls.Clear();

    public Task<StoredKeyInfo> GenerateAsync(string alias, KeyType keyType, CancellationToken ct = default)
    {
        _calls.Add(nameof(GenerateAsync));
        return _inner.GenerateAsync(alias, keyType, ct);
    }

    public Task<StoredKeyInfo> ImportAsync(string alias, KeyPair keyPair, CancellationToken ct = default)
    {
        _calls.Add(nameof(ImportAsync));
        return _inner.ImportAsync(alias, keyPair, ct);
    }

    public Task<StoredKeyInfo?> GetInfoAsync(string alias, CancellationToken ct = default)
    {
        _calls.Add(nameof(GetInfoAsync));
        return _inner.GetInfoAsync(alias, ct);
    }

    public Task<byte[]> SignAsync(string alias, ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        _calls.Add(nameof(SignAsync));
        return _inner.SignAsync(alias, data, ct);
    }

    public Task<byte[]> DeriveSharedSecretAsync(string alias, ReadOnlyMemory<byte> peerPublicKey, CancellationToken ct = default)
    {
        _calls.Add(nameof(DeriveSharedSecretAsync));
        return _inner.DeriveSharedSecretAsync(alias, peerPublicKey, ct);
    }

    public async Task<ISigner> CreateSignerAsync(string alias, CancellationToken ct = default)
    {
        _calls.Add(nameof(CreateSignerAsync));

        // Bind the signer to the wrapper (not the inner store) so its SignAsync calls
        // are recorded; key info is read through the recorded GetInfoAsync path.
        var info = await GetInfoAsync(alias, ct).ConfigureAwait(false)
            ?? throw new KeyNotFoundException($"No key with alias '{alias}'.");
        return new KeyStoreSigner(this, alias, info.KeyType, info.PublicKey);
    }

    public Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default)
    {
        _calls.Add(nameof(ListAsync));
        return _inner.ListAsync(ct);
    }

    public Task<bool> DeleteAsync(string alias, CancellationToken ct = default)
    {
        _calls.Add(nameof(DeleteAsync));
        return _inner.DeleteAsync(alias, ct);
    }
}
