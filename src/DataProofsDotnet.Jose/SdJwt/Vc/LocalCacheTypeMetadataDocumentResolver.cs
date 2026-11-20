namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// The default, offline <see cref="ITypeMetadataDocumentResolver"/> (PRD FR-10 / FR-17 posture): an immutable local
/// cache of document octets keyed by <c>vct</c> (draft-ietf-oauth-sd-jwt-vc-27 §5.3.4, §7.5). It never performs network
/// or file I/O, serves only the documents seeded at construction, and returns <c>null</c> for any other reference.
/// Seed it with the exact bytes the publisher serves, so that <c>vct#integrity</c> and <c>extends#integrity</c> match.
/// Thread-safe.
/// </summary>
public sealed class LocalCacheTypeMetadataDocumentResolver : ITypeMetadataDocumentResolver
{
    private readonly Dictionary<string, byte[]> _byReference;

    /// <summary>Create a resolver backed by a fixed reference → document octets map.</summary>
    /// <param name="documents">The pre-seeded documents; each value is copied.</param>
    public LocalCacheTypeMetadataDocumentResolver(IReadOnlyDictionary<string, byte[]> documents)
    {
        ArgumentNullException.ThrowIfNull(documents);
        _byReference = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var (reference, document) in documents)
        {
            ArgumentNullException.ThrowIfNull(document);
            _byReference[reference] = document.ToArray();
        }
    }

    /// <inheritdoc />
    public Task<byte[]?> ResolveDocumentAsync(string reference, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reference);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(_byReference.TryGetValue(reference, out var document) ? document.ToArray() : null);
    }
}
