using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// AC-2: the W3C RDF Dataset Canonicalization (RDFC-1.0) test suite, driven by the vendored
/// <c>manifest.jsonld</c> and fed through this library's PUBLIC canonicalizer interface
/// (<see cref="IRdfCanonicalizer"/> / <see cref="RdfcDocumentCanonicalizer"/>), never raw
/// dotNetRDF. Evaluation tests byte-compare the canonical N-Quads; map tests compare the
/// issued-identifier map; the single negative-evaluation entry must raise
/// <see cref="RdfCanonicalizationException"/>. No case is skipped, and the processed entry
/// count is asserted against the count recorded in the suite's PROVENANCE.md.
/// </summary>
public sealed class RdfCanonicalizationConformanceTests
{
    // Recorded in tests/fixtures/w3c/rdf-canon/PROVENANCE.md: 86 manifest entries
    // (64 RDFC10EvalTest + 21 RDFC10MapTest + 1 RDFC10NegativeEvalTest).
    private const int ExpectedManifestEntryCount = 86;

    public enum CaseKind
    {
        Eval,
        Map,
        NegativeEval,
    }

    public sealed record ManifestCase(string Id, CaseKind Kind, string ActionFile, string? ResultFile, RdfCanonicalizationHashAlgorithm Hash)
    {
        public override string ToString() => Id;
    }

    public static TheoryData<ManifestCase> Cases()
    {
        var data = new TheoryData<ManifestCase>();
        foreach (var entry in LoadManifest())
        {
            data.Add(entry);
        }

        return data;
    }

    [Fact]
    public void Manifest_EntryCount_MatchesProvenance()
        => LoadManifest().Count.Should().Be(ExpectedManifestEntryCount);

    [Theory]
    [MemberData(nameof(Cases))]
    public void Rdfc10_Case_MatchesExpectedResult(ManifestCase test)
    {
        var canonicalizer = new RdfcDocumentCanonicalizer();
        var input = ReadCanonInput(test.ActionFile);

        switch (test.Kind)
        {
            case CaseKind.Eval:
                var canonical = canonicalizer.CanonicalizeNQuads(input, test.Hash);
                canonical.Should().Be(ReadCanonInput(test.ResultFile!));
                break;

            case CaseKind.Map:
                var map = canonicalizer.CanonicalizeNQuadsToMap(input, test.Hash);
                var expected = JsonSerializer.Deserialize<Dictionary<string, string>>(ReadCanonInput(test.ResultFile!))!;
                map.Should().BeEquivalentTo(expected);
                break;

            case CaseKind.NegativeEval:
                // The "poison" clique graph must be rejected, not silently produced.
                var act = () => canonicalizer.CanonicalizeNQuads(input, test.Hash);
                act.Should().Throw<RdfCanonicalizationException>();
                break;

            default:
                throw new InvalidOperationException($"Unknown case kind {test.Kind}.");
        }
    }

    private static List<ManifestCase> LoadManifest()
    {
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(Fixtures.PathTo("w3c", "rdf-canon", "manifest.jsonld")));
        var entries = manifest.RootElement.GetProperty("entries");

        var cases = new List<ManifestCase>();
        foreach (var entry in entries.EnumerateArray())
        {
            var id = entry.GetProperty("id").GetString()!;
            var type = entry.GetProperty("type").GetString()!;
            var action = entry.GetProperty("action").GetString()!;
            var result = entry.TryGetProperty("result", out var r) ? r.GetString() : null;
            var hash = entry.TryGetProperty("hashAlgorithm", out var h) && h.GetString() == "SHA384"
                ? RdfCanonicalizationHashAlgorithm.Sha384
                : RdfCanonicalizationHashAlgorithm.Sha256;

            var kind = type switch
            {
                "rdfc:RDFC10EvalTest" => CaseKind.Eval,
                "rdfc:RDFC10MapTest" => CaseKind.Map,
                "rdfc:RDFC10NegativeEvalTest" => CaseKind.NegativeEval,
                _ => throw new InvalidOperationException($"Unknown manifest test type '{type}'."),
            };

            cases.Add(new ManifestCase(id, kind, action, result, hash));
        }

        return cases;
    }

    // Manifest action/result paths are "rdfc10/testNNN-*.nq" relative to the suite root.
    private static string ReadCanonInput(string relativePath)
        => File.ReadAllText(Fixtures.PathTo("w3c", "rdf-canon", relativePath.Replace('/', Path.DirectorySeparatorChar)));
}
