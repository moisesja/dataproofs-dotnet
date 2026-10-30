using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using FluentAssertions;
using VDS.RDF;
using VDS.RDF.Parsing;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// RDFC-1.0 byte for byte against <c>rdf-canonize</c>, the implementation the reference Data Integrity
/// stack signs with (PR #42). The W3C rdf-canon suite does not exercise the blank-node ties where
/// dotNetRDF 3.5.1 deviates (dotnetrdf/dotnetrdf#917), so this corpus guards the local copy of its
/// canonicalizer. Canonical bytes are what a proof signs, so a difference here is a proof that does not
/// verify across implementations, in either direction.
/// </summary>
public sealed partial class RdfCanonicalizationDifferentialTests
{
    private const int ExpectedCaseCount = 1870;

    private sealed record Case(string Family, RdfCanonicalizationHashAlgorithm Hash, string Input, string Expected);

    private static readonly Lazy<IReadOnlyList<Case>> Corpus = new(() =>
    {
        using var corpus = JsonDocument.Parse(Fixtures.ReadText("generated", "rdfc-differential.json"));
        return corpus.RootElement.GetProperty("cases").EnumerateArray().Select(entry => new Case(
            entry.GetProperty("family").GetString()!,
            entry.GetProperty("hash").GetString() == "SHA384" ? RdfCanonicalizationHashAlgorithm.Sha384 : RdfCanonicalizationHashAlgorithm.Sha256,
            entry.GetProperty("input").GetString()!,
            entry.GetProperty("expected").GetString()!)).ToList();
    });

    private static readonly RdfcDocumentCanonicalizer Canonicalizer = new();

    [Fact]
    public void Corpus_IsByteIdenticalToRdfCanonize()
    {
        Corpus.Value.Should().HaveCount(ExpectedCaseCount);
        Corpus.Value.Select(c => c.Hash).Distinct().Should().HaveCount(2, "both hash algorithms are covered");

        var different = Corpus.Value.Where(c => Canonicalizer.CanonicalizeNQuads(c.Input, c.Hash) != c.Expected).ToList();

        different.Should().BeEmpty("the first differing input is:\n" + different.FirstOrDefault()?.Input);
    }

    [Fact]
    public void Corpus_WouldCatchTheUpstreamDefect()
    {
        // A corpus that dotNetRDF's own class passes would prove nothing about the local copy.
        var different = Corpus.Value
            .Where(c => c.Hash == RdfCanonicalizationHashAlgorithm.Sha256 && UpstreamCanonical(c.Input) != c.Expected)
            .ToList();

        different.Should().HaveCountGreaterThan(200);
        different.Select(c => c.Family).Should().Contain("credential, distinct items sharing a nested value")
            .And.Contain("credential, same-looking items with distinct children")
            .And.Contain("graph with self-references");
    }

    [Fact]
    public void Corpus_IsStableUnderReshuffledStatementsAndRenamedLabels()
    {
        // Canonical means the same bytes however the document happened to be written.
        var random = new Random(40);
        foreach (var sample in Corpus.Value.Where((_, i) => i % 7 == 0))
        {
            var labels = new Dictionary<string, string>();
            var lines = sample.Input.Split('\n', StringSplitOptions.RemoveEmptyEntries).OrderBy(_ => random.Next());
            var rewritten = Label().Replace(string.Join('\n', lines) + "\n", label =>
            {
                if (!labels.TryGetValue(label.Value, out var renamed))
                {
                    labels[label.Value] = renamed = "_:r" + random.Next(1_000_000) + "x" + labels.Count;
                }

                return renamed;
            });

            Canonicalizer.CanonicalizeNQuads(rewritten, sample.Hash).Should().Be(sample.Expected);
        }
    }

    [GeneratedRegex(@"_:[A-Za-z0-9]+")]
    private static partial Regex Label();

    [Fact]
    public void CredentialWithRepeatedNestedValue_MatchesRdfCanonizeByteForByte()
    {
        // Two licences from the same country, an ordinary credential. Expected output from jsonld.js 9.0.0
        // with rdf-canonize 5.0.0 and rdfDirection: 'i18n-datatype' over the bundled credentials/v2 context.
        // dotNetRDF 3.5.1 swaps _:c14n2 and _:c14n3 here, so a proof over it verified nowhere else.
        const string credential = """
            {"@context":["https://www.w3.org/ns/credentials/v2",{"@vocab":"https://e.example/vocab#"}],
             "id":"urn:uuid:40404040-0000-4000-8000-000000000048","type":"VerifiableCredential","issuer":"did:example:issuer",
             "credentialSubject":{"id":"did:example:alice","licenses":[
               {"label":"entry 0 of 48","country":{"code":"US"}},{"label":"entry 1 of 48","country":{"code":"US"}}]}}
            """;
        const string expected =
            "<did:example:alice> <https://e.example/vocab#licenses> _:c14n0 .\n"
            + "<did:example:alice> <https://e.example/vocab#licenses> _:c14n1 .\n"
            + "<urn:uuid:40404040-0000-4000-8000-000000000048> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n"
            + "<urn:uuid:40404040-0000-4000-8000-000000000048> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:alice> .\n"
            + "<urn:uuid:40404040-0000-4000-8000-000000000048> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer> .\n"
            + "_:c14n0 <https://e.example/vocab#country> _:c14n3 .\n"
            + "_:c14n0 <https://e.example/vocab#label> \"entry 0 of 48\" .\n"
            + "_:c14n1 <https://e.example/vocab#country> _:c14n2 .\n"
            + "_:c14n1 <https://e.example/vocab#label> \"entry 1 of 48\" .\n"
            + "_:c14n2 <https://e.example/vocab#code> \"US\" .\n"
            + "_:c14n3 <https://e.example/vocab#code> \"US\" .\n";

        var canonical = Canonicalizer.CanonicalizeJsonLd(JsonDocument.Parse(credential).RootElement.Clone());

        Encoding.UTF8.GetString(canonical).Should().Be(expected);
    }

    [Theory]
    [InlineData(1001)]
    [InlineData(5000)]
    public void ManyBlankNodes_WithoutATie_Canonicalize(int count)
    {
        // dotNetRDF walked every blank node, tied or not, against a budget of 1,000, so a document with
        // 1,001 of them could not be canonicalized at all. Without a tie the specification walks none.
        var dataset = new StringBuilder();
        for (var i = 0; i < count; i++)
        {
            dataset.Append($"_:n{i} <urn:p> \"v{i}\" .\n");
        }

        Canonicalizer.CanonicalizeNQuads(dataset.ToString()).Split('\n', StringSplitOptions.RemoveEmptyEntries).Should().HaveCount(count);
    }

    [Fact]
    public void ManyIdenticalFlatItems_Canonicalize()
    {
        // Ties that need one walk each stay within the budget however many there are.
        var dataset = new StringBuilder();
        for (var i = 0; i < 6000; i++)
        {
            dataset.Append($"<urn:s> <urn:p> _:n{i} .\n_:n{i} <urn:q> \"same\" .\n");
        }

        Canonicalizer.CanonicalizeNQuads(dataset.ToString()).Split('\n', StringSplitOptions.RemoveEmptyEntries).Should().HaveCount(12000);
    }

    [Fact]
    public void LargeClique_IsRefused_NotWorkedThrough()
    {
        // The W3C poison case at a larger size. The work budget is what stops it.
        var clique = new StringBuilder();
        for (var i = 0; i < 100; i++)
        {
            for (var j = 0; j < 100; j++)
            {
                if (i != j)
                {
                    clique.Append($"_:n{i} <urn:p> _:n{j} .\n");
                }
            }
        }

        var act = () => Canonicalizer.CanonicalizeNQuads(clique.ToString());

        act.Should().Throw<RdfCanonicalizationException>().WithInnerException<Exception>().WithMessage("Recursion limit reached");
    }

    public static TheoryData<int> StackSizes() => new() { 0, 256 * 1024, 128 * 1024 };

    [Theory]
    [MemberData(nameof(StackSizes))]
    public void LongChainOfTiedBlankNodes_IsRefused_NotAStackOverflow(int stackSize)
    {
        // Explicit identifiers can make a chain arbitrarily long, and the walk recurses once per node. A
        // stack overflow cannot be caught and would end the verifier's process, so it must be a refusal,
        // however small the stack. Zero is the runtime's default size.
        var chain = new StringBuilder();
        for (var i = 0; i < 3000; i++)
        {
            chain.Append($"_:n{i} <urn:p> _:n{i + 1} .\n");
        }

        Exception? refusal = null;
        var thread = new Thread(
            () =>
            {
                try
                {
                    Canonicalizer.CanonicalizeNQuads(chain.ToString());
                }
                catch (RdfCanonicalizationException ex)
                {
                    refusal = ex;
                }
            },
            stackSize);
        thread.Start();
        thread.Join();

        refusal.Should().NotBeNull();
    }

    [Fact]
    public void NonAsciiPredicate_IsHashedAsWritten()
    {
        // Expected from jsonld.js 9.0.0 with rdf-canonize 5.0.0. dotNetRDF hashed the percent-encoded form
        // of a predicate (Uri.AbsoluteUri), so the labels of the last two statements came out swapped.
        const string document = """
            {"@context":{"a":{"@id":"https://e.example/日"},"b":{"@id":"https://e.example/é"}},
             "@graph":[{"@id":"_:e5","a":{"@id":"_:e1"}},{"@id":"_:e6","b":{"@id":"_:e4"}},{"@id":"_:e0","b":{"@id":"_:e5"}}]}
            """;
        const string expected =
            "_:c14n0 <https://e.example/日> _:c14n2 .\n"
            + "_:c14n3 <https://e.example/é> _:c14n1 .\n"
            + "_:c14n4 <https://e.example/é> _:c14n0 .\n";

        var canonical = Canonicalizer.CanonicalizeJsonLd(JsonDocument.Parse(document).RootElement.Clone());

        Encoding.UTF8.GetString(canonical).Should().Be(expected);
    }

    [Fact]
    public void BlankNodeRepeatedAcrossManyGraphs_TakesOneWalk()
    {
        // The list of related nodes names one node twenty times, which is one permutation, not 20!.
        // Eleven took dotNetRDF about 24 seconds in a document of 619 bytes.
        var dataset = new StringBuilder("_:r <urn:u> \"unique\" .\n");
        for (var i = 0; i < 20; i++)
        {
            dataset.Append($"_:a <urn:p> _:r <urn:g{i}> .\n_:b <urn:p> _:r <urn:g{i}> .\n");
        }

        FinishesInTime(() => Canonicalizer.CanonicalizeNQuads(dataset.ToString())).Should().BeNull();
    }

    [Fact]
    public void ManyDistinctRelatedNodes_AreRefusedBeforeAnyPermutation()
    {
        // See the fixture's provenance: this input spends no walks, so only the up-front check stops it.
        var bomb = Fixtures.ReadText("generated", "rdfc-permutation-bomb.nq");

        FinishesInTime(() => Canonicalizer.CanonicalizeNQuads(bomb))
            .Should().BeOfType<RdfCanonicalizationException>().Which.InnerException!.Message.Should().Be("Recursion limit reached");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(256 * 1024)]
    public void BlankNodesWithThousandsOfRelatedNodes_AreRefused_NotAStackOverflow(int stackSize)
    {
        // Permute recurses once per related node, so two tied hubs of 20,000 children, 877 KB of N-Quads or
        // a similar JSON-LD document, killed the process on every version up to 1.5.0.
        var hubs = new StringBuilder();
        for (var i = 0; i < 20000; i++)
        {
            hubs.Append($"_:a <urn:p> _:a{i} .\n_:b <urn:p> _:b{i} .\n");
        }

        Exception? refusal = null;
        var thread = new Thread(() => refusal = FinishesInTime(() => Canonicalizer.CanonicalizeNQuads(hubs.ToString())), stackSize);
        thread.Start();
        thread.Join();

        refusal.Should().BeOfType<RdfCanonicalizationException>();
    }

    [Fact]
    public void ChainAsDeepAsJsonInputAllows_Canonicalizes()
    {
        // The 64-level nesting limit (FR-2) in a document of like objects: done as specified this costs
        // about the square of its length, which dotNetRDF's budget of 1,000 walks would refuse.
        var chain = new StringBuilder();
        for (var i = 0; i < 64; i++)
        {
            chain.Append($"_:n{i} <urn:p> _:n{i + 1} .\n");
        }

        Canonicalizer.CanonicalizeNQuads(chain.ToString()).Split('\n', StringSplitOptions.RemoveEmptyEntries).Should().HaveCount(64);
    }

    // Null when the work finished, the exception when it was refused. A hang fails the test, with a limit
    // well above what a bounded run takes, instead of hanging the build.
    private static Exception? FinishesInTime(Action work)
    {
        var run = Task.Run(() =>
        {
            try
            {
                work();
                return null;
            }
            catch (RdfCanonicalizationException ex)
            {
                return (Exception)ex;
            }
        });

        run.Wait(TimeSpan.FromSeconds(60)).Should().BeTrue("hostile input must not run unbounded");
        return run.Result;
    }

    // Upstream refuses some of these outright: its budget runs out on documents the specification handles.
    private static string UpstreamCanonical(string nQuads)
    {
        var store = new TripleStore();
        new NQuadsParser().Load(store, new StringReader(nQuads));
        try
        {
            return new RdfCanonicalizer("SHA256").Canonicalize(store).SerializedNQuads;
        }
        catch (Exception ex) when (ex.Message == "Recursion limit reached")
        {
            return string.Empty;
        }
    }
}
