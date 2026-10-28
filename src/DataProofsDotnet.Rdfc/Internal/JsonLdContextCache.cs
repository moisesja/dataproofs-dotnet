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
/// <c>@base</c> members.
/// </para>
/// </remarks>
internal sealed class JsonLdContextCache(IDocumentLoader documentLoader)
{
    private readonly Dictionary<string, LoadedContextDocument> _loaded = new(StringComparer.Ordinal);

    /// <summary>Whether any context loaded so far holds a non-null <c>@base</c> member.</summary>
    public bool AnySetsBase { get; private set; }

    /// <summary>Processor options that load contexts through this cache.</summary>
    public JsonLdProcessorOptions Options(bool withoutBase) => new()
    {
        DocumentLoader = (uri, _) => Load(uri, withoutBase),
        // Reports what expansion drops (undefined terms, malformed language tags) as warnings
        // instead of discarding it silently (issue #36).
        SafeMode = true,
    };

    // Bridges the public IDocumentLoader to dotNetRDF's JSON-LD document-loader callback.
    // Newtonsoft's JToken lives only on this side of the boundary.
    private RemoteDocument Load(Uri uri, bool withoutBase)
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
            if (withoutBase)
            {
                token = JsonLdLossAudit.WithoutBase(token);
            }
        }

        return new RemoteDocument
        {
            Document = token,
            DocumentUrl = loaded.DocumentUrl,
        };
    }
}
