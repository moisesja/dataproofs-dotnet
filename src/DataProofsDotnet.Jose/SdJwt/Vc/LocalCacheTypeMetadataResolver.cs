using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// The default, offline <see cref="ITypeMetadataResolver"/> (PRD FR-10 / FR-17 posture): an
/// immutable local cache keyed by <c>vct</c>. It NEVER performs network or file I/O — it only
/// serves documents the consumer pre-seeded at construction, and returns <c>null</c> for any
/// unknown <c>vct</c> (fail-closed). A consumer who wants network retrieval supplies a different
/// <see cref="ITypeMetadataResolver"/>. Thread-safe.
/// </summary>
public sealed class LocalCacheTypeMetadataResolver : ITypeMetadataResolver
{
    private readonly IReadOnlyDictionary<string, JsonObject> _byVct;

    /// <summary>Create a resolver backed by a fixed <c>vct</c> → Type Metadata document map.</summary>
    /// <param name="documents">The pre-seeded documents; each value is deep-cloned and stored immutably.</param>
    public LocalCacheTypeMetadataResolver(IReadOnlyDictionary<string, JsonObject> documents)
    {
        ArgumentNullException.ThrowIfNull(documents);
        var copy = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        foreach (var (vct, doc) in documents)
        {
            ArgumentNullException.ThrowIfNull(doc);
            copy[vct] = (JsonObject)doc.DeepClone();
        }
        _byVct = copy;
    }

    /// <summary>Create an empty offline resolver that resolves no <c>vct</c> (always returns <c>null</c>).</summary>
    public LocalCacheTypeMetadataResolver()
        : this(new Dictionary<string, JsonObject>()) { }

    /// <inheritdoc />
    public Task<JsonObject?> ResolveAsync(string vct, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(vct);
        cancellationToken.ThrowIfCancellationRequested();
        var doc = _byVct.TryGetValue(vct, out var found) ? (JsonObject)found.DeepClone() : null;
        return Task.FromResult(doc);
    }
}
