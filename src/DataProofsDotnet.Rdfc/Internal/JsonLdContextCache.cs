using Newtonsoft.Json.Linq;
using VDS.RDF.JsonLd;

namespace DataProofsDotnet.Rdfc.Internal;

/// <summary>
/// The contexts one canonicalization loads, each read once from the caller's
/// <see cref="IDocumentLoader"/>, so that every expansion of the input sees the same ones (issue #36).
/// </summary>
/// <remarks>
/// <para>
/// The data-loss audit and the parse expand the input separately. A loader that answered
/// differently the second time could otherwise get past the audit input that the parse then drops.
/// Each expansion gets a fresh token, so none sees another's state.
/// </para>
/// <para>
/// The cache also records whether a loaded context sets <c>@base</c>. dotNetRDF ignores a remote
/// context's own <c>@base</c>, but honors one in a property- or type-scoped context the remote context
/// defines, because it processes scoped contexts as local ones (adversarial review, F1). The
/// <c>@base</c> check (<see cref="JsonLdLossAudit"/>) therefore also expands with
/// <see cref="Options"/><c>(withoutBase: true)</c>, which serves every context without its
/// <c>@base</c> members. It also collects the terms loaded contexts define as aliases of <c>@set</c>
/// and <c>@index</c>, for the check on a set object's dropped <c>@index</c>.
/// </para>
/// </remarks>
internal sealed class JsonLdContextCache(IDocumentLoader documentLoader)
{
    private readonly Dictionary<string, LoadedContextDocument> _loaded = new(StringComparer.Ordinal);

    /// <summary>Whether any context loaded so far holds a non-null <c>@base</c> member.</summary>
    public bool AnySetsBase { get; private set; }

    private readonly HashSet<string> _setAliases = new(StringComparer.Ordinal);
    private readonly HashSet<string> _indexAliases = new(StringComparer.Ordinal);

    /// <summary>The terms loaded contexts define as aliases of <c>@set</c>.</summary>
    public IReadOnlyCollection<string> SetAliases => _setAliases;

    /// <summary>The terms loaded contexts define as aliases of <c>@index</c>.</summary>
    public IReadOnlyCollection<string> IndexAliases => _indexAliases;

    /// <summary>Processor options that load contexts through this cache, served as <paramref name="view"/>.</summary>
    public JsonLdProcessorOptions Options(ContextView view) => new()
    {
        DocumentLoader = (uri, _) => Load(uri, view),
        // Reports what expansion drops (undefined terms, malformed language tags) as warnings
        // instead of discarding it silently (issue #36).
        SafeMode = true,
    };

    // Bridges the public IDocumentLoader to dotNetRDF's JSON-LD document-loader callback.
    // Newtonsoft's JToken lives only on this side of the boundary.
    private RemoteDocument Load(Uri uri, ContextView view)
    {
        if (!_loaded.TryGetValue(uri.AbsoluteUri, out var loaded))
        {
            loaded = documentLoader.Load(uri);
            _loaded.Add(uri.AbsoluteUri, loaded);
        }

        JToken token;
        try
        {
            token = JToken.Parse(loaded.Content);
        }
        catch (Exception ex)
        {
            throw new RdfCanonicalizationException($"The context '{uri.AbsoluteUri}' did not contain valid JSON.", ex);
        }

        if (JsonLdLossAudit.HasBase(token))
        {
            AnySetsBase = true;
            if (view == ContextView.WithoutBase)
            {
                token = JsonLdLossAudit.WithoutBase(token);
            }
        }

        JsonLdLossAudit.CollectAliases(token, _setAliases, _indexAliases);

        return new RemoteDocument
        {
            Document = token,
            DocumentUrl = loaded.DocumentUrl,
        };
    }
}

/// <summary>How <see cref="JsonLdContextCache"/> serves the contexts it loaded.</summary>
internal enum ContextView
{
    /// <summary>As the loader returned them.</summary>
    AsLoaded,

    /// <summary>Without their <c>@base</c> members.</summary>
    WithoutBase,
}
