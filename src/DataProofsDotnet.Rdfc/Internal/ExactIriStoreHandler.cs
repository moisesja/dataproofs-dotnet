using VDS.RDF;
using VDS.RDF.Parsing.Handlers;
using VDS.RDF.Writing.Formatting;

namespace DataProofsDotnet.Rdfc.Internal;

/// <summary>
/// A <see cref="StoreHandler"/> that records whether any IRI it receives would be spelled
/// differently in the canonical N-Quads than in the input (issue #36).
/// </summary>
/// <remarks>
/// dotNetRDF keeps IRIs as <see cref="Uri"/> values and prints them with <see cref="Uri.ToString"/>,
/// which removes dot segments, decodes percent-encoded unreserved and non-ASCII characters, lowers
/// the scheme and host, and drops a default port. RDF compares IRIs as strings, so a respelled IRI
/// signs a different name than the document carries, and every spelling that normalizes alike
/// would verify. The check compares each IRI's <see cref="Uri.OriginalString"/> (the parser's input)
/// with what <see cref="NQuads11Formatter"/>, the canonicalizer's serializer, prints for it. It runs
/// on every quad before the store deduplicates, so a respelled duplicate cannot hide behind the
/// spelling it collapses into. Parsing continues; the caller checks <see cref="RespelledIri"/>.
/// One instance per parse.
/// </remarks>
internal sealed class ExactIriStoreHandler(ITripleStore store) : StoreHandler(store)
{
    private readonly NQuads11Formatter _formatter = new();

    /// <summary>Whether any IRI received so far would be respelled in the canonical N-Quads.</summary>
    public bool RespelledIri { get; private set; }

    protected override bool HandleTripleInternal(Triple t)
    {
        Check(t, graph: null);
        return base.HandleTripleInternal(t);
    }

    protected override bool HandleQuadInternal(Triple t, IRefNode graph)
    {
        Check(t, graph);
        return base.HandleQuadInternal(t, graph);
    }

    private void Check(Triple t, INode? graph)
    {
        if (!RespelledIri)
        {
            RespelledIri = Respells(t.Subject) || Respells(t.Predicate) || Respells(t.Object) || Respells(graph);
        }
    }

    private bool Respells(INode? node) => node switch
    {
        IUriNode uriNode => Respells(uriNode.Uri),
        ILiteralNode { DataType: { } datatype } => Respells(datatype),
        _ => false,
    };

    private bool Respells(Uri uri) => !string.Equals(_formatter.FormatUri(uri), uri.OriginalString, StringComparison.Ordinal);
}
