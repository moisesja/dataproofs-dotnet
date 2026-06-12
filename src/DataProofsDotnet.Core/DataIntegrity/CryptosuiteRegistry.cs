using System.Collections.Concurrent;

namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// An open registry of Data Integrity cryptosuites keyed by cryptosuite name (FR-4).
/// Thread-safe; registration replaces any existing suite of the same name (last
/// registration wins).
/// </summary>
public sealed class CryptosuiteRegistry
{
    private readonly ConcurrentDictionary<string, ICryptosuite> _suites = new(StringComparer.Ordinal);

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
        _suites[suite.Name] = suite;
    }

    /// <summary>Returns the suite registered under <paramref name="name"/>, or <c>null</c>.</summary>
    public ICryptosuite? GetByName(string? name)
        => string.IsNullOrEmpty(name) ? null : _suites.GetValueOrDefault(name);

    /// <summary>The names of all registered suites.</summary>
    public IReadOnlyCollection<string> RegisteredNames => _suites.Keys.ToArray();
}
