using Newtonsoft.Json.Linq;
using VDS.RDF.JsonLd;
using VDS.RDF.JsonLd.Syntax;

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
/// The audit's probes expand the input again with every context rewritten the way the input is
/// (<see cref="Options"/> with a <c>serve</c> function), so the processor resolves the rewritten
/// terms in its own active context. The cache records what triggers them: whether a loaded context
/// sets <c>@base</c> (dotNetRDF ignores a remote context's own <c>@base</c>, but honors one in a
/// property- or type-scoped context the remote context defines, because it processes scoped
/// contexts as local ones; adversarial review, F1), and whether one names <c>@index</c>.
/// </para>
/// </remarks>
internal sealed class JsonLdContextCache(IDocumentLoader documentLoader)
{
    private readonly Dictionary<string, LoadedContextDocument> _loaded = new(StringComparer.Ordinal);

    /// <summary>Whether any context loaded so far holds a non-null <c>@base</c> member.</summary>
    public bool AnySetsBase { get; private set; }

    /// <summary>Whether any context loaded so far defines a term as <c>@index</c>.</summary>
    public bool AnyNamesIndex { get; private set; }

    /// <summary>
    /// Processor options that load contexts through this cache, each served through
    /// <paramref name="serve"/> when one is given.
    /// </summary>
    public JsonLdProcessorOptions Options(Func<JToken, JToken>? serve = null) => new()
    {
        DocumentLoader = (uri, _) => Load(uri, serve),
        // Reports what expansion drops (undefined terms, malformed language tags) as warnings
        // instead of discarding it silently (issue #36).
        SafeMode = true,
        // Carries a string's base direction in its datatype IRI (https://www.w3.org/ns/i18n#<language>_<direction>,
        // JSON-LD 1.1 API §8.6), the representation the reference Data Integrity implementations sign
        // with. Without it dotNetRDF drops @direction silently, so "ltr" and "rtl" signed the same
        // bytes (issue #40). Expansion ignores it, so the audit's probes are unaffected.
        RdfDirection = JsonLdRdfDirectionMode.I18NDatatype,
    };

    // Bridges the public IDocumentLoader to dotNetRDF's JSON-LD document-loader callback.
    // Newtonsoft's JToken lives only on this side of the boundary.
    private RemoteDocument Load(Uri uri, Func<JToken, JToken>? serve)
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

        AnySetsBase |= JsonLdLossAudit.HasBase(token);
        AnyNamesIndex |= JsonLdLossAudit.NamesIndex(token);

        return new RemoteDocument
        {
            Document = serve is null ? token : serve(token),
            DocumentUrl = loaded.DocumentUrl,
        };
    }
}
