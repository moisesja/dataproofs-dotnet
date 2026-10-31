using FluentAssertions;
using VDS.RDF;
using VDS.RDF.Parsing;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// The canary for <c>Internal/Rdfc10Canonicalizer.cs</c>, a local copy of dotNetRDF's RDFC-1.0
/// implementation with its defects fixed (dotnetrdf/dotnetrdf#917, PR #42). This calls dotNetRDF's own
/// class and pins that it still deviates from the specification. When a dotNetRDF upgrade makes this
/// fail, the copy has served its purpose: switch <c>RdfcDocumentCanonicalizer</c> back to the upstream
/// class, delete the copy and this test, and check that <see cref="RdfCanonicalizationDifferentialTests"/>
/// still passes, which also shows whether the work and depth limits survived.
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

    // rdf-canonize 5.0.0, and an independent implementation written from the specification's text.
    private const string SpecifiedCanonicalForm =
        "_:c14n0 <https://e.example/p> _:c14n1 .\n"
        + "_:c14n0 <https://e.example/p> _:c14n3 .\n"
        + "_:c14n1 <https://e.example/q> _:c14n2 .\n"
        + "_:c14n2 <https://e.example/n> \"ball\" .\n"
        + "_:c14n3 <https://e.example/q> _:c14n4 .\n"
        + "_:c14n4 <https://e.example/n> \"ball\" .\n";

    [Fact]
    public void ThisLibrary_ProducesTheSpecifiedForm()
        => new RdfcDocumentCanonicalizer().CanonicalizeNQuads(TiedSubtrees).Should().Be(SpecifiedCanonicalForm);

    [Fact]
    public void SortOrder_FollowsRdfCanonize_NotTheSpecificationsCodePoints()
    {
        // A deliberate deviation: the specification sorts by code point, which would put U+FF21 before
        // U+1F600. rdf-canonize, and so the proofs in the field, sort by UTF-16 code unit.
        var grinning = char.ConvertFromUtf32(0x1F600);
        const string fullwidthA = "\uFF21";
        var input = $"<urn:s> <urn:p> \"{fullwidthA}\" .\n<urn:s> <urn:p> \"{grinning}\" .\n";

        new RdfcDocumentCanonicalizer().CanonicalizeNQuads(input)
            .Should().Be($"<urn:s> <urn:p> \"{grinning}\" .\n<urn:s> <urn:p> \"{fullwidthA}\" .\n");
    }

    [Fact]
    public void DotNetRdfsOwnClass_StillDeviates()
    {
        var store = new TripleStore();
        new NQuadsParser().Load(store, new StringReader(TiedSubtrees));

        var upstream = new RdfCanonicalizer("SHA256").Canonicalize(store).SerializedNQuads;

        upstream.Should().NotBe(SpecifiedCanonicalForm, "this fails once dotNetRDF fixes dotnetrdf/dotnetrdf#917; see the class remarks");
    }
}
