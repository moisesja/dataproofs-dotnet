using System.Text;
using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// Sanity checks that the public RDFC canonicalizer reproduces the W3C eddsa-rdfc-2022
/// worked vector's canonical document N-Quads byte-for-byte (proves JSON-LD expansion +
/// RDFC-1.0 + offline context loading all line up before the suites consume it).
/// </summary>
public sealed class CanonicalizerSanityTests
{
    [Fact]
    public void CanonicalizeJsonLd_AlumniCredential_ReproducesSpecCanonicalNQuads()
    {
        var unsigned = Fixtures.ReadText("w3c", "vc-di-eddsa", "TestVectors", "unsigned.json");
        var expected = Fixtures.ReadText("w3c", "vc-di-eddsa", "TestVectors", "eddsa-rdfc-2022", "canonDocDataInt.txt");

        var canonicalizer = new RdfcDocumentCanonicalizer();
        using var doc = JsonDocument.Parse(unsigned);
        var canonical = canonicalizer.CanonicalizeJsonLd(doc.RootElement);

        Encoding.UTF8.GetString(canonical).Should().Be(expected);
    }
}
