using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// A canary for a known deviation of dotNetRDF's RDFC-1.0 implementation from the specification
/// (dotnetrdf/dotnetrdf#917, found by the adversarial review of PR #42). When two blank nodes tie at
/// the first degree and each owns further blank nodes, the Hash N-Degree Quads algorithm issues the
/// identifiers depth-first (a, then a's x, then b, then b's y); dotNetRDF issues them breadth-first
/// (a, b, x, y), so its canonical form differs from <c>rdf-canonize</c>'s, and a signature over such
/// a dataset does not verify across implementations. The W3C rdf-canon suite has no case with this
/// shape. This test pins the deviation: when a dotNetRDF upgrade makes it fail, the limitation is
/// gone, so remove the CHANGELOG and PRD notes, turn this into a positive case, and close #917.
/// </summary>
public sealed class RdfCanonicalizationDeviationTests
{
    private const string TiedSubtrees =
        "_:s <https://e.example/p> _:a .\n"
        + "_:s <https://e.example/p> _:b .\n"
        + "_:a <https://e.example/q> _:x .\n"
        + "_:b <https://e.example/q> _:y .\n"
        + "_:x <https://e.example/n> \"ball\" .\n"
        + "_:y <https://e.example/n> \"ball\" .\n";

    // rdf-canonize 4.x (the specification editors' implementation) and a hand run of the algorithm.
    private const string SpecifiedCanonicalForm =
        "_:c14n0 <https://e.example/p> _:c14n1 .\n"
        + "_:c14n0 <https://e.example/p> _:c14n3 .\n"
        + "_:c14n1 <https://e.example/q> _:c14n2 .\n"
        + "_:c14n2 <https://e.example/n> \"ball\" .\n"
        + "_:c14n3 <https://e.example/q> _:c14n4 .\n"
        + "_:c14n4 <https://e.example/n> \"ball\" .\n";

    // dotNetRDF 3.5.1.
    private const string DotNetRdfCanonicalForm =
        "_:c14n0 <https://e.example/p> _:c14n1 .\n"
        + "_:c14n0 <https://e.example/p> _:c14n2 .\n"
        + "_:c14n1 <https://e.example/q> _:c14n3 .\n"
        + "_:c14n2 <https://e.example/q> _:c14n4 .\n"
        + "_:c14n3 <https://e.example/n> \"ball\" .\n"
        + "_:c14n4 <https://e.example/n> \"ball\" .\n";

    [Fact]
    public void TiedSubtrees_StillCanonicalizeAsDotNetRdfDoes_NotAsSpecified()
    {
        var canonical = new RdfcDocumentCanonicalizer().CanonicalizeNQuads(TiedSubtrees);

        canonical.Should().NotBe(SpecifiedCanonicalForm, "this canary fails once dotNetRDF fixes dotnetrdf/dotnetrdf#917; see the class remarks");
        canonical.Should().Be(DotNetRdfCanonicalForm);
    }
}
