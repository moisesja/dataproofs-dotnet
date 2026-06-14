using System.Collections.Concurrent;

namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// An open registry of Data Integrity cryptosuites keyed by cryptosuite name (FR-4).
/// Thread-safe; registration replaces any existing suite of the same name (last
/// registration wins).
/// </summary>
/// <remarks>
/// A secondary index maps a proof <c>type</c> to the suite that declares it via
/// <see cref="ICryptosuite.SupportedProofTypes"/>, so the verify pipeline can dispatch
/// legacy Linked-Data-Signature proofs (which name their algorithm by <c>type</c> and carry
/// no <c>cryptosuite</c>) through <see cref="GetByProofType"/>. The default Data Integrity
/// type (<see cref="DataIntegrityProof.DataIntegrityProofType"/>) is deliberately excluded
/// from this index: the shipped 2022/2019 suites all share that single type and are always
/// disambiguated by <c>cryptosuite</c> name, never by type.
/// <para>
/// If two suites registered under <em>different</em> names both declare the same non-default
/// proof <c>type</c>, the type index is last-registration-wins (mirroring the name index).
/// This is benign: both suites claim the type and each fully re-validates the proof in its
/// own <see cref="ICryptosuite.VerifyProof"/>, so a "wrong" selection fails closed rather than
/// accepting. Shipping suites that overlap on a legacy type is therefore discouraged.
/// </para>
/// </remarks>
public sealed class CryptosuiteRegistry
{
    private readonly ConcurrentDictionary<string, ICryptosuite> _suites = new(StringComparer.Ordinal);

    /// <summary>Secondary index: non-default proof <c>type</c> → suite (legacy suites only).</summary>
    private readonly ConcurrentDictionary<string, ICryptosuite> _suitesByProofType = new(StringComparer.Ordinal);

    /// <summary>Serializes registration so the two indexes update atomically; reads stay lock-free.</summary>
    private readonly object _registrationLock = new();

    /// <summary>Creates an empty registry.</summary>
    public CryptosuiteRegistry()
    {
    }

    /// <summary>
    /// Creates a registry pre-populated with the JCS suites this package ships:
    /// <c>eddsa-jcs-2022</c> and <c>ecdsa-jcs-2019</c> (FR-5).
    /// </summary>
    public static CryptosuiteRegistry CreateDefault()
    {
        var registry = new CryptosuiteRegistry();
        registry.Register(new EddsaJcs2022Cryptosuite());
        registry.Register(new EcdsaJcs2019Cryptosuite());
        return registry;
    }

    /// <summary>Registers a suite under <see cref="ICryptosuite.Name"/>, replacing any previous registration.</summary>
    public void Register(ICryptosuite suite)
    {
        ArgumentNullException.ThrowIfNull(suite);
        ArgumentException.ThrowIfNullOrEmpty(suite.Name);

        var newTypes = NonDefaultProofTypes(suite).ToHashSet(StringComparer.Ordinal);

        lock (_registrationLock)
        {
            _suites.TryGetValue(suite.Name, out var previous);

            // Publish the new suite's type entries BEFORE pruning the old ones, so a type
            // claimed by both the replaced and the replacing suite is repointed atomically —
            // a concurrent GetByProofType never observes it transiently absent.
            foreach (var type in newTypes)
            {
                _suitesByProofType[type] = suite;
            }

            _suites[suite.Name] = suite;

            // Prune the previous suite's type entries that the new suite no longer claims.
            // Value-matched so a different-named suite that owns the same type is left intact
            // (last-registration-wins; see the class remarks), and re-registering a suite that
            // still claims the type stays idempotent.
            if (previous is not null)
            {
                foreach (var type in NonDefaultProofTypes(previous))
                {
                    if (!newTypes.Contains(type))
                    {
                        ((ICollection<KeyValuePair<string, ICryptosuite>>)_suitesByProofType)
                            .Remove(new KeyValuePair<string, ICryptosuite>(type, previous));
                    }
                }
            }
        }
    }

    /// <summary>Returns the suite registered under <paramref name="name"/>, or <c>null</c>.</summary>
    public ICryptosuite? GetByName(string? name)
        => string.IsNullOrEmpty(name) ? null : _suites.GetValueOrDefault(name);

    /// <summary>
    /// Returns the suite that declares <paramref name="type"/> in its
    /// <see cref="ICryptosuite.SupportedProofTypes"/>, or <c>null</c>. Resolves only
    /// legacy/type-named suites: the default Data Integrity type
    /// (<see cref="DataIntegrityProof.DataIntegrityProofType"/>), <c>null</c>, and empty
    /// always return <c>null</c>, because those proofs are dispatched by <c>cryptosuite</c>
    /// name (<see cref="GetByName"/>), never by type. When two differently named suites
    /// declare the same type, the most recently registered one is returned (see the class
    /// remarks); the verify pipeline re-confirms the returned suite claims the type.
    /// </summary>
    public ICryptosuite? GetByProofType(string? type)
        => string.IsNullOrEmpty(type) ? null : _suitesByProofType.GetValueOrDefault(type);

    /// <summary>The names of all registered suites.</summary>
    public IReadOnlyCollection<string> RegisteredNames => _suites.Keys.ToArray();

    /// <summary>The suite's declared proof types excluding the default Data Integrity type.</summary>
    private static IEnumerable<string> NonDefaultProofTypes(ICryptosuite suite)
        => (suite.SupportedProofTypes ?? []).Where(
            type => !string.IsNullOrEmpty(type)
                && !string.Equals(type, DataIntegrityProof.DataIntegrityProofType, StringComparison.Ordinal));
}
