using VDS.RDF;
using VDS.RDF.Parsing.Handlers;
using VDS.RDF.Writing.Formatting;

namespace DataProofsDotnet.Rdfc.Internal;

/// <summary>
/// A <see cref="StoreHandler"/> that records whether any IRI it receives would be spelled
/// differently in the canonical N-Quads than in the input, and whether the store merged
/// statements that RDF holds distinct (issue #36).
/// </summary>
/// <remarks>
/// <para>
/// dotNetRDF keeps IRIs as <see cref="Uri"/> values and prints them with <see cref="Uri.ToString"/>,
/// which removes dot segments, decodes percent-encoded unreserved and non-ASCII characters, lowers
/// the scheme and host, and drops a default port. RDF compares IRIs as strings, so a respelled IRI
/// signs a different name than the document carries, and every spelling that normalizes alike
/// would verify. The check compares each IRI's <see cref="Uri.OriginalString"/> (the parser's input)
/// with what <see cref="NQuads11Formatter"/>, the canonicalizer's serializer, prints for it. It runs
/// on every quad before the store deduplicates, so a respelled duplicate cannot hide behind the
/// spelling it collapses into. Parsing continues; the caller checks <see cref="RespelledIri"/>.
/// </para>
/// <para>
/// Spelled exactly is not enough: the store deduplicates with dotNetRDF's node equality, which
/// compares parsed URI components (so <c>https://e.example</c> equals <c>https://e.example/</c>)
/// and, in a host that sets loose literal equality, literal values. Two statements RDF holds
/// distinct could then collapse into one, and the second would go unsigned (PR #37 review). The
/// store also looks graphs up by that equality, so a statement for graph <c>https://g.example/</c>
/// lands in graph <c>https://g.example</c> and is printed under that name: it moves graph without
/// any statement being lost (adversarial review, F2). So the handler keeps every distinct statement
/// it received in its exact N-Quads form, and <see cref="MergedStatements"/> compares that set
/// with the statements the store will print, graph names included. Exact duplicates share one
/// form and stay harmless.
/// </para>
/// <para>
/// It also records an unpaired UTF-16 surrogate in any term (<see cref="UnpairedSurrogate"/>):
/// N-Quads input can spell one as <c>\uDC00</c>, and UTF-8 output would carry it as U+FFFD, the
/// same bytes as a real U+FFFD (adversarial review, F4). One instance per parse.
/// </para>
/// </remarks>
internal sealed class ExactIriStoreHandler(ITripleStore store) : StoreHandler(store)
{
    private readonly NQuads11Formatter _formatter = new();
    private readonly HashSet<string> _statements = new(StringComparer.Ordinal);

    /// <summary>Whether any IRI received so far would be respelled in the canonical N-Quads.</summary>
    public bool RespelledIri { get; private set; }

    /// <summary>Whether any term received so far holds an unpaired UTF-16 surrogate.</summary>
    public bool UnpairedSurrogate { get; private set; }

    /// <summary>
    /// Whether the statements the store will print, graph names included, differ from the distinct
    /// statements it was given.
    /// </summary>
    public bool MergedStatements
    {
        get
        {
            var stored = new HashSet<string>(StringComparer.Ordinal);
            foreach (var graph in Store.Graphs)
            {
                foreach (var triple in graph.Triples)
                {
                    stored.Add(_formatter.Format(triple, graph.Name));
                }
            }

            return !stored.SetEquals(_statements);
        }
    }

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

    private void Check(Triple t, IRefNode? graph)
    {
        if (!RespelledIri)
        {
            RespelledIri = Respells(t.Subject) || Respells(t.Predicate) || Respells(t.Object) || Respells(graph);
        }

        if (!UnpairedSurrogate)
        {
            UnpairedSurrogate = HasUnpairedSurrogate(t.Subject) || HasUnpairedSurrogate(t.Predicate)
                || HasUnpairedSurrogate(t.Object) || HasUnpairedSurrogate(graph);
        }

        _statements.Add(_formatter.Format(t, graph));
    }

    private bool Respells(INode? node) => node switch
    {
        IUriNode uriNode => Respells(uriNode.Uri),
        ILiteralNode { DataType: { } datatype } => Respells(datatype),
        _ => false,
    };

    private bool Respells(Uri uri) => !string.Equals(_formatter.FormatUri(uri), uri.OriginalString, StringComparison.Ordinal);

    private static bool HasUnpairedSurrogate(INode? node) => node switch
    {
        IUriNode uriNode => HasUnpairedSurrogate(uriNode.Uri.OriginalString),
        ILiteralNode literal => HasUnpairedSurrogate(literal.Value) || HasUnpairedSurrogate(literal.Language)
            || (literal.DataType is { } datatype && HasUnpairedSurrogate(datatype.OriginalString)),
        _ => false,
    };

    private static bool HasUnpairedSurrogate(string text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                i++;
            }
            else if (char.IsSurrogate(text[i]))
            {
                return true;
            }
        }

        return false;
    }
}
