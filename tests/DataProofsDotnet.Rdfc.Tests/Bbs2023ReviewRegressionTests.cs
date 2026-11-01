using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;
using DataProofsDotnet.Rdfc.Internal;
using DataProofsDotnet.Rdfc.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

public sealed class Bbs2023ReviewRegressionTests
{
    private const string V2 = "https://www.w3.org/ns/credentials/v2";
    private const string NestedContext = "bbs-2023 selection requires @context only at the document root; nested @context members are not supported.";
    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement.Clone();
    private static DataIntegrityProof Options() => new()
    {
        Cryptosuite = Bbs2023Cryptosuite.CryptosuiteName,
        Created = "2026-10-30T00:00:00Z",
        VerificationMethod = "did:example:issuer#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    private static (byte[] Sk, byte[] Hmac) Keys()
    {
        var material = Fx.Json("w3c", "vc-di-bbs", "TestVectors", "BBSKeyMaterial.json");
        return (Convert.FromHexString(material.GetProperty("privateKeyHex").GetString()!),
            Convert.FromHexString(material.GetProperty("hmacKeyString").GetString()!));
    }

    private static JsonElement Secure(JsonElement document, DataIntegrityProof proof)
        => Fx.Mutate(document, node => node["proof"] = JsonSerializer.SerializeToNode(proof, DataProofsJsonOptions.Default));

    private static bool Verify(Bbs2023Cryptosuite suite, JsonElement reveal, byte[] sk)
        => suite.VerifyProof(Fx.Mutate(reveal, node => node.Remove("proof")),
            reveal.GetProperty("proof").Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!,
            PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, Fx.KeyGen.FromPrivateKey(KeyType.Bls12381G2, sk).PublicKey)).Verified;

    [Fact]
    public void BlankNodeToken_EndsAtCanonicalAsciiSpace_NotUnicodeWhitespace()
    {
        // U+1680 is inside PN_CHARS_BASE's U+037F–U+1FFF range, although .NET calls it whitespace.
        const string label = "a\u1680b";
        var map = new Dictionary<string, string> { [label] = "b0" };
        BlankNodeLabels.RelabelAndSort([$"_:{label} <urn:p> \"_:{label}\" .\n"], map)
            .Should().Equal($"_:b0 <urn:p> \"_:{label}\" .\n");
    }

    [BbsFact]
    public async Task MandatoryPointer_CannotChangePredicateToAnotherExistingStatement()
    {
        var document = Parse("""
            {"@context":["https://www.w3.org/ns/credentials/v2",{"inner":"urn:inner","note":"urn:outerNote"}],
             "id":"urn:doc","type":"VerifiableCredential","issuer":"did:example:issuer",
             "credentialSubject":{"id":"did:example:alice","description":"public",
               "inner":{"id":"urn:innerNode","@context":{"note":"urn:mandatoryNote"},
                        "note":"must reveal","urn:outerNote":"must reveal"}}}
            """);
        var (sk, hmac) = Keys();
        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(document, Options(), sk, hmac,
            ["/credentialSubject/inner/note"]);
        await act.Should().ThrowAsync<ProofGenerationException>().WithMessage(NestedContext);
    }

    [BbsFact]
    public async Task Derivation_RejectsAnAddedNestedContextEvenWhenTheRdfIsUnchanged()
    {
        var document = Parse("""
            {"@context":"https://www.w3.org/ns/credentials/v2","id":"urn:doc","type":"VerifiableCredential",
             "issuer":"did:example:issuer","credentialSubject":{"id":"did:example:alice","name":"Alice"}}
            """);
        var (sk, hmac) = Keys();
        var suite = new Bbs2023Cryptosuite();
        var proof = await suite.CreateBaseProofAsync(document, Options(), sk, hmac, ["/issuer"]);
        var secured = Fx.Mutate(Secure(document, proof), node => node["credentialSubject"]!["@context"] = V2);
        var act = () => suite.DeriveProof(secured, ["/credentialSubject/name"], new byte[4]);
        act.Should().Throw<ProofGenerationException>().WithMessage(NestedContext);
    }

    [BbsTheory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task WholeJsonLiteral_PreservesNullsDespiteACollidingSibling(bool mandatory)
    {
        var document = Parse("""
            {"@context":"https://www.w3.org/ns/credentials/v2","id":"urn:doc","type":"VerifiableCredential",
             "issuer":"did:example:issuer","credentialSubject":{"id":"did:example:alice","description":"public",
               "urn:json":[{"@type":"@json","@value":[null,1]},{"@type":"@json","@value":[1]}]}}
            """);
        const string pointer = "/credentialSubject/urn:json/0";
        var (sk, hmac) = Keys();
        var suite = new Bbs2023Cryptosuite();
        var proof = await suite.CreateBaseProofAsync(document, Options(), sk, hmac, [mandatory ? pointer : "/issuer"]);
        var reveal = suite.DeriveProof(Secure(document, proof),
            [mandatory ? "/credentialSubject/description" : pointer], new byte[4]);
        Verify(suite, reveal, sk).Should().BeTrue();
        reveal.GetProperty("credentialSubject").GetProperty("urn:json")[0].GetProperty("@value")[0]
            .ValueKind.Should().Be(JsonValueKind.Null);
        var altered = Fx.Mutate(reveal, node =>
            ((JsonArray)node["credentialSubject"]!["urn:json"]![0]!["@value"]!).RemoveAt(0));
        Verify(suite, altered, sk).Should().BeFalse("the original literal, not its sibling, was disclosed");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OverlappingSelections_PreserveCopiedArraysAndDensifyOnlySelectionHoles(bool parentFirst)
    {
        var document = Parse("""{"@context":{},"items":[{"data":[null,[null,1]]},{"data":[null,2]},{"data":[3]}]}""");
        string[] pointers = parentFirst ? ["/items/1", "/items/1/data", "/items/2"] : ["/items/1/data", "/items/1", "/items/2"];
        var selected = JsonPointer.SelectJsonLd(document, pointers)!;
        var expected = JsonNode.Parse("""{"@context":{},"items":[{"data":[null,2]},{"data":[3]}]}""");
        JsonNode.DeepEquals(selected, expected).Should().BeTrue();
    }

    [Theory]
    [InlineData("/items/2/data/1", "/items", "/items/1/data/1")]
    [InlineData("/items", "/items/2/data/1", "/items/1/data/1")]
    [InlineData("/items/2/data/1", "/items/1/data/1", "/items")]
    public void ReplacedSparseSelections_DoNotCompactWholeCopiedArrays(string first, string second, string third)
    {
        const string raw = """{"items":[{"data":[null,[null,0]]},{"data":[null,[null,1]]},{"data":[null,[null,2]]}]}""";
        JsonNode.DeepEquals(JsonPointer.SelectJsonLd(Parse(raw), [first, second, third]), JsonNode.Parse(raw))
            .Should().BeTrue();
    }

    [Theory]
    [InlineData("/items/2/data/1", "/items/1/data/1")]
    [InlineData("/items/1/data/1", "/items/2/data/1")]
    public void NestedSparseSelections_KeepNullsInsideSelectedArrays(string first, string second)
    {
        const string raw = """{"items":[{"data":[null,[null,0]]},{"data":[null,[null,1]]},{"data":[null,[null,2]]}]}""";
        const string expected = """{"items":[{"data":[[null,1]]},{"data":[[null,2]]}]}""";
        JsonNode.DeepEquals(JsonPointer.SelectJsonLd(Parse(raw), [first, second]), JsonNode.Parse(expected))
            .Should().BeTrue();
    }

    [BbsTheory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task UnicodeStatementOrdering_PreservesMandatorySelection(int mandatoryIndex)
    {
        var document = Parse("""
            {"@context":"https://www.w3.org/ns/credentials/v2","type":"VerifiableCredential",
             "issuer":"did:example:issuer","credentialSubject":{"name":["Ａ","😀"],"description":"public"}}
            """);
        var (sk, hmac) = Keys();
        var suite = new Bbs2023Cryptosuite();
        var proof = await suite.CreateBaseProofAsync(document, Options(), sk, hmac, [$"/credentialSubject/name/{mandatoryIndex}"]);
        var reveal = suite.DeriveProof(Secure(document, proof), ["/credentialSubject/description"], new byte[4]);
        Verify(suite, reveal, sk).Should().BeTrue();
        var altered = Fx.Mutate(reveal, node => node["credentialSubject"]!["name"]![0] = mandatoryIndex == 0 ? "😀" : "Ａ");
        Verify(suite, altered, sk).Should().BeFalse();
    }

    [BbsTheory]
    [InlineData("_:foo")]
    [InlineData("_:foo-bar")]
    [InlineData("_:foo_bar")]
    [InlineData("_:foo.bar")]
    [InlineData("_:é")]
    [InlineData("_:中")]
    public async Task ExplicitBlankNodeIdentifiers_RoundTrip(string label)
    {
        var document = Parse("""
            {"@context":"https://www.w3.org/ns/credentials/v2","id":"urn:doc","type":"VerifiableCredential",
             "issuer":"did:example:issuer","credentialSubject":{"id":"LABEL","name":"Alice","description":"public"}}
            """.Replace("LABEL", label, StringComparison.Ordinal));
        var (sk, hmac) = Keys();
        var suite = new Bbs2023Cryptosuite();
        var proof = await suite.CreateBaseProofAsync(document, Options(), sk, hmac, ["/issuer"]);
        var reveal = suite.DeriveProof(Secure(document, proof), ["/credentialSubject/name"], new byte[4]);
        Verify(suite, reveal, sk).Should().BeTrue();
    }

    [BbsFact]
    public async Task ProofContext_RemainsWhenTheDocumentIsRecompacted()
    {
        var document = Parse("""
            {"@context":["https://www.w3.org/ns/credentials/v2",{"customFlag":"urn:flag"}],
             "id":"urn:doc","type":"VerifiableCredential","issuer":"did:example:issuer",
             "credentialSubject":{"id":"did:example:alice","name":"Alice","description":"public"}}
            """);
        var (sk, hmac) = Keys();
        var suite = new Bbs2023Cryptosuite();
        var options = Options() with { AdditionalProperties = new Dictionary<string, JsonElement> { ["customFlag"] = Parse("\"value\"") } };
        var proof = await suite.CreateBaseProofAsync(document, options, sk, hmac, ["/issuer"]);
        // The removed mapping is unused by the document, but still needed by the proof extension.
        var secured = Fx.Mutate(Secure(document, proof), node => node["@context"] = V2);
        var reveal = suite.DeriveProof(secured, ["/credentialSubject/name"], new byte[4]);
        Verify(suite, reveal, sk).Should().BeTrue();
        Verify(suite, Fx.Mutate(reveal, node => ((JsonObject)node["proof"]!).Remove("@context")), sk)
            .Should().BeFalse("the proof context is necessary, not just redundant metadata");
    }
}
