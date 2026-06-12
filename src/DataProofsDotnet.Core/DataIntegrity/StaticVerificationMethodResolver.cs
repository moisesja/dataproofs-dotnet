namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// A dictionary-backed <see cref="IVerificationMethodResolver"/> (FR-7) carrying
/// explicit per-method relationship sets, so controller authorization — including its
/// negative cases — can be exercised in tests and samples without any DID machinery.
/// Lookup is by exact ordinal match on the verification-method id (substring or prefix
/// matching would enable id-spoofing).
/// </summary>
public sealed class StaticVerificationMethodResolver : IVerificationMethodResolver
{
    private readonly Dictionary<string, ResolvedVerificationMethod> _methods;

    /// <summary>Creates a resolver over the given methods, keyed by <see cref="ResolvedVerificationMethod.Id"/>.</summary>
    /// <exception cref="ArgumentException">Two methods share the same id.</exception>
    public StaticVerificationMethodResolver(IEnumerable<ResolvedVerificationMethod> methods)
    {
        ArgumentNullException.ThrowIfNull(methods);

        _methods = new Dictionary<string, ResolvedVerificationMethod>(StringComparer.Ordinal);
        foreach (var method in methods)
        {
            ArgumentNullException.ThrowIfNull(method, nameof(methods));
            if (!_methods.TryAdd(method.Id, method))
            {
                throw new ArgumentException($"Duplicate verification method id '{method.Id}'.", nameof(methods));
            }
        }
    }

    /// <inheritdoc />
    public Task<ResolvedVerificationMethod?> ResolveAsync(
        string verificationMethodUrl,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verificationMethodUrl);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(_methods.GetValueOrDefault(verificationMethodUrl));
    }
}
