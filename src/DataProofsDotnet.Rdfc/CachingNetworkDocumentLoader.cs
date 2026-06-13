using System.Net.Http;

namespace DataProofsDotnet.Rdfc;

/// <summary>
/// An opt-in JSON-LD document loader (FR-10) that serves the offline-bundled contexts
/// first and, for anything outside that set, fetches over the network and caches the
/// result in-process. Ported from <c>zcap-dotnet</c>'s <c>CachedContextLoader</c>,
/// generalized to cache fetched documents and to be injectable.
/// </summary>
/// <remarks>
/// <para>
/// This loader is <b>never</b> the default. The default posture is offline-only
/// (<see cref="OfflineDocumentLoader"/>); a caller wanting network retrieval must
/// construct this type deliberately and pass it to the canonicalizer. Network retrieval
/// during signature verification is an SSRF/availability hazard — the opt-in is the point.
/// </para>
/// <para>
/// The cache is a plain dictionary (no caching package is referenced — PRD §2.2 forbids
/// <c>Microsoft.Extensions.Caching.Memory</c> for <c>Rdfc</c>): unbounded, no TTL/eviction.
/// Tuned caching strategy is out of scope (FR-10). Instances are thread-safe.
/// </para>
/// </remarks>
public sealed class CachingNetworkDocumentLoader : IDocumentLoader, IDisposable
{
    private readonly IDocumentLoader _offline;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, LoadedContextDocument> _cache = new(StringComparer.Ordinal);

    /// <summary>
    /// Creates a caching network loader over a dedicated <see cref="HttpClient"/> and the
    /// offline-bundled contexts.
    /// </summary>
    public CachingNetworkDocumentLoader()
        : this(new HttpClient(), ownsHttpClient: true, OfflineDocumentLoader.Instance)
    {
    }

    /// <summary>
    /// Creates a caching network loader over a caller-supplied <see cref="HttpClient"/>
    /// (not disposed by this loader) and an optional offline loader for the bundled set.
    /// </summary>
    /// <param name="httpClient">The HTTP client used for network fetches.</param>
    /// <param name="offlineLoader">The loader consulted first; defaults to the offline loader.</param>
    public CachingNetworkDocumentLoader(HttpClient httpClient, IDocumentLoader? offlineLoader = null)
        : this(httpClient, ownsHttpClient: false, offlineLoader ?? OfflineDocumentLoader.Instance)
    {
    }

    private CachingNetworkDocumentLoader(HttpClient httpClient, bool ownsHttpClient, IDocumentLoader offline)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(offline);
        _httpClient = httpClient;
        _ownsHttpClient = ownsHttpClient;
        _offline = offline;
    }

    /// <inheritdoc />
    public LoadedContextDocument Load(Uri url)
    {
        ArgumentNullException.ThrowIfNull(url);

        // Bundled contexts are always served offline (no network, no cache needed).
        try
        {
            return _offline.Load(url);
        }
        catch (RdfCanonicalizationException)
        {
            // Not bundled: fall through to the network path.
        }

        lock (_gate)
        {
            if (_cache.TryGetValue(url.AbsoluteUri, out var cached))
            {
                return cached;
            }
        }

        var fetched = Fetch(url);

        lock (_gate)
        {
            // Last writer wins; benign for an idempotent GET.
            _cache[url.AbsoluteUri] = fetched;
        }

        return fetched;
    }

    private LoadedContextDocument Fetch(Uri url)
    {
        if (url.Scheme != Uri.UriSchemeHttps && url.Scheme != Uri.UriSchemeHttp)
        {
            throw new RdfCanonicalizationException(
                $"Refusing to fetch context '{url.AbsoluteUri}': only http(s) retrieval is supported.");
        }

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Accept.ParseAdd("application/ld+json");
            request.Headers.Accept.ParseAdd("application/json;q=0.9");

            using var response = _httpClient.Send(request);
            response.EnsureSuccessStatusCode();

            var content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            var documentUrl = response.RequestMessage?.RequestUri ?? url;
            return new LoadedContextDocument(documentUrl, content);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            throw new RdfCanonicalizationException($"Failed to retrieve context '{url.AbsoluteUri}'.", ex);
        }
    }

    /// <summary>Disposes the owned <see cref="HttpClient"/>, if any.</summary>
    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }
}
