using VDS.RDF;
using VDS.RDF.Writing;
using VDS.RDF.Writing.Formatting;

namespace DataProofsDotnet.Rdfc.Internal;

/// <summary>
/// The N-Quads formatter with blank-node labels written as they are. dotNetRDF's formatter checks each
/// new label against every value of a dictionary (<c>BlankNodeOutputMapper.GetOutputID</c>), so
/// formatting a dataset took time quadratic in its blank nodes: a hostile 2.7 MB document kept a
/// verifier busy for over a minute. Labels are unique within a store, so the comparisons and output
/// that use this formatter see the same statements.
/// </summary>
internal sealed class DirectLabelNQuadsFormatter : NQuads11Formatter
{
    /// <inheritdoc />
    protected override string FormatBlankNode(IBlankNode b, TripleSegment? segment) => "_:" + b.InternalID;
}
