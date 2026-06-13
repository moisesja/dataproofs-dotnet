using System.Reflection;

namespace DataProofsDotnet.Rdfc;

/// <summary>
/// The default JSON-LD document loader (FR-10): serves version-pinned, provenance-tracked
/// copies of the core W3C contexts the v1 features require — embedded as assembly resources
/// — and <b>fails closed</b> on any context outside the bundled set.
/// </summary>
/// <remarks>
/// <para>
/// Verification is deterministic and performs no ambient network I/O: a security
/// operation's correctness never depends on a remote host being reachable. A context the
/// loader does not bundle is rejected with a <see cref="RdfCanonicalizationException"/>
/// rather than fetched. Callers who need network retrieval must explicitly construct a
/// <see cref="CachingNetworkDocumentLoader"/>.
/// </para>
/// <para>
/// The bundled contexts and their provenance are recorded in the package's
/// <c>Contexts/PROVENANCE.md</c> (and <c>tests/fixtures/contexts/PROVENANCE.md</c>, the
/// source of record). This loader is immutable and thread-safe (NFR-4).
/// </para>
/// </remarks>
public sealed class OfflineDocumentLoader : IDocumentLoader
{
    /// <summary>
    /// A shared, immutable instance. Loading is stateless, so this is sufficient for every
    /// canonicalization in a process.
    /// </summary>
    public static OfflineDocumentLoader Instance { get; } = new();

    // Context URL -> embedded resource logical name. Ordinal keying so URL matching is exact.
    private static readonly IReadOnlyDictionary<string, string> ResourceByUrl =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["https://www.w3.org/ns/credentials/v2"] = "DataProofsDotnet.Rdfc.Contexts.credentials-v2.jsonld",
            ["https://www.w3.org/ns/credentials/examples/v2"] = "DataProofsDotnet.Rdfc.Contexts.credentials-examples-v2.jsonld",
            ["https://www.w3.org/2018/credentials/v1"] = "DataProofsDotnet.Rdfc.Contexts.credentials-v1.jsonld",
            ["https://w3id.org/security/data-integrity/v2"] = "DataProofsDotnet.Rdfc.Contexts.data-integrity-v2.jsonld",
            ["https://w3id.org/security/data-integrity/v1"] = "DataProofsDotnet.Rdfc.Contexts.data-integrity-v1.jsonld",
            ["https://w3id.org/security/multikey/v1"] = "DataProofsDotnet.Rdfc.Contexts.multikey-v1.jsonld",
            ["https://w3id.org/security/bbs/v1"] = "DataProofsDotnet.Rdfc.Contexts.bbs-v1.jsonld",
            ["https://w3id.org/security/suites/jws-2020/v1"] = "DataProofsDotnet.Rdfc.Contexts.jws-2020-v1.jsonld",
        };

    private static readonly Assembly ResourceAssembly = typeof(OfflineDocumentLoader).Assembly;

    /// <summary>Creates an offline loader. Prefer <see cref="Instance"/>.</summary>
    public OfflineDocumentLoader()
    {
    }

    /// <summary>The set of context URLs this loader serves offline.</summary>
    public static IReadOnlyCollection<string> BundledContextUrls => (IReadOnlyCollection<string>)ResourceByUrl.Keys;

    /// <inheritdoc />
    public LoadedContextDocument Load(Uri url)
    {
        ArgumentNullException.ThrowIfNull(url);

        if (!ResourceByUrl.TryGetValue(url.AbsoluteUri, out var resourceName))
        {
            // Fail closed: the loader never reaches the network (FR-10).
            throw new RdfCanonicalizationException(
                $"The context '{url.AbsoluteUri}' is not among the offline document loader's bundled contexts; " +
                "the default loader does not perform network retrieval. Construct a CachingNetworkDocumentLoader to opt in.");
        }

        using var stream = ResourceAssembly.GetManifestResourceStream(resourceName)
            ?? throw new RdfCanonicalizationException(
                $"The embedded context resource for '{url.AbsoluteUri}' is missing from the assembly.");
        using var reader = new StreamReader(stream);
        return new LoadedContextDocument(url, reader.ReadToEnd());
    }
}
