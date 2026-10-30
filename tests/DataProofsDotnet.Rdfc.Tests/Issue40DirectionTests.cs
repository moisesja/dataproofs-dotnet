using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;
using DataProofsDotnet.Rdfc.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// Issue #40: a string's base direction is carried in the canonical form as the JSON-LD 1.1
/// <c>rdfDirection: i18n-datatype</c> literal (<c>"x"^^&lt;https://www.w3.org/ns/i18n#ar_rtl&gt;</c>),
/// the representation the reference Data Integrity implementations sign with. 1.5.0 refused every
/// <c>@direction</c>, and earlier versions dropped it, so <c>ltr</c> and <c>rtl</c> signed the same
/// bytes. A boolean or a number with a direction is still refused: dotNetRDF (like jsonld.js) types it
/// as an XSD literal and drops the direction, where JSON-LD 1.1 API §8.2.2 step 12 would apply the i18n
/// datatype to its lexical form. Direction-free input is unchanged, which the
/// W3C vector tests and <see cref="Issue36DataLossTests.CarriedDocuments"/> pin.
/// </summary>
public sealed class Issue40DirectionTests
{
    private const string V2 = "https://www.w3.org/ns/credentials/v2";
    private const string I18n = "https://www.w3.org/ns/i18n#";
    private const string Name = "https://schema.org/name";

    // The canonicalizer's message phrases, asserted literally so a changed meaning fails here.
    private const string Direction = "uses @direction on a value that is not a string, which the canonical form does not carry";
    private const string MalformedLanguageTag = "has a language tag that is not well-formed";
    private const string Index = "uses @index, which the canonical form does not carry";
    private const string IgnoredContent = "has content that JSON-LD processing ignores";

    private static readonly RdfcDocumentCanonicalizer Canonicalizer = new();

    /// <summary>A credential over <paramref name="contexts"/> whose own terms are all defined, plus <paramref name="members"/>.</summary>
    private static string Vc(string members, string contexts = "\"" + V2 + "\"")
        => "{\"@context\":[" + contexts + "],\"id\":\"urn:uuid:40404040-0000-4000-8000-000000000040\","
            + "\"type\":\"VerifiableCredential\",\"issuer\":\"did:example:issuer\"," + members + "}";

    private static string Subject(string members) => "\"credentialSubject\":{\"id\":\"did:example:alice\"," + members + "}";

    /// <summary>The credentials/v2 context followed by an inline context object.</summary>
    private static string V2With(string inlineContext) => "\"" + V2 + "\"," + inlineContext;

    /// <summary>A value object with a base direction, as VCDM 2.0 §11.1 writes <c>name</c> and <c>description</c>.</summary>
    private static string Directional(string value, string? language, string direction)
        => "{\"@value\":\"" + value + "\"" + (language is null ? "" : ",\"@language\":\"" + language + "\"") + ",\"@direction\":\"" + direction + "\"}";

    /// <summary>The i18n literal JSON-LD 1.1 API §8.2.2 produces: language lowercased, empty when absent.</summary>
    private static string Literal(string value, string language, string direction) => "\"" + value + "\"^^<" + I18n + language + "_" + direction + ">";

    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement.Clone();

    private static string Canonical(string json) => Encoding.UTF8.GetString(Canonicalizer.CanonicalizeJsonLd(Parse(json)));

    // ------------------------------------------------------------------ the canonicalizer

    public static TheoryData<string, string, string> CarriedDocuments() => new()
    {
        // case, document, an N-Quads fragment the output must contain verbatim
        // The VCDM 2.0 test suite's 4.06 shapes: name, description, issuer.name with language and direction.
        { "credential name", Vc("\"name\":" + Directional("x", "en", "ltr") + "," + Subject("\"name\":\"n\"")), "<urn:uuid:40404040-0000-4000-8000-000000000040> <" + Name + "> " + Literal("x", "en", "ltr") + " ." },
        { "credential description", Vc("\"description\":" + Directional("x", "en", "ltr") + "," + Subject("\"name\":\"n\"")), "<https://schema.org/description> " + Literal("x", "en", "ltr") + " ." },
        { "issuer name", Vc(Subject("\"name\":\"n\"")).Replace("\"issuer\":\"did:example:issuer\"", "\"issuer\":{\"id\":\"did:example:issuer\",\"name\":" + Directional("x", "en", "ltr") + "}"), "<did:example:issuer> <" + Name + "> " + Literal("x", "en", "ltr") + " ." },
        { "subject name, rtl", Vc(Subject("\"name\":" + Directional("x", "ar", "rtl"))), "<did:example:alice> <" + Name + "> " + Literal("x", "ar", "rtl") + " ." },
        { "direction without a language", Vc(Subject("\"name\":" + Directional("x", null, "rtl"))), Literal("x", "", "rtl") },
        { "language tag lowercased", Vc(Subject("\"name\":" + Directional("x", "en-US", "rtl"))), Literal("x", "en-us", "rtl") },
        { "inline context default direction", Vc(Subject("\"name\":\"x\""), V2With("{\"@direction\":\"rtl\"}")), "<did:example:alice> <" + Name + "> " + Literal("x", "", "rtl") + " ." },
        { "inline context default language and direction", Vc(Subject("\"name\":\"x\""), V2With("{\"@language\":\"ar\",\"@direction\":\"rtl\"}")), Literal("x", "ar", "rtl") },
        { "language map with a default direction", Vc(Subject("\"label\":{\"en\":\"x\",\"@none\":\"y\"}"), V2With("{\"label\":{\"@id\":\"" + Name + "\",\"@container\":\"@language\"},\"@direction\":\"rtl\"}")), Literal("x", "en", "rtl") },
        { "language map's @none entry with a default direction", Vc(Subject("\"label\":{\"en\":\"x\",\"@none\":\"y\"}"), V2With("{\"label\":{\"@id\":\"" + Name + "\",\"@container\":\"@language\"},\"@direction\":\"rtl\"}")), Literal("y", "", "rtl") },
        { "inside a list", Vc(Subject("\"steps\":[" + Directional("x", "ar", "rtl") + "]"), V2With("{\"steps\":{\"@id\":\"https://e.example/vocab#steps\",\"@container\":\"@list\"}}")), "<http://www.w3.org/1999/02/22-rdf-syntax-ns#first> " + Literal("x", "ar", "rtl") + " ." },
        { "aliased @direction", Vc(Subject("\"name\":{\"@value\":\"x\",\"dir\":\"rtl\"}"), V2With("{\"dir\":\"@direction\"}")), Literal("x", "", "rtl") },
        { "context default direction reset to null", Vc(Subject("\"name\":\"x\""), V2With("{\"@direction\":\"rtl\"},{\"@direction\":null}")), "<did:example:alice> <" + Name + "> \"x\" ." },
        { "@direction inside a @json literal is data", Vc(Subject("\"data\":{\"@value\":\"x\",\"@direction\":\"rtl\"}"), V2With("{\"data\":{\"@id\":\"https://e.example/vocab#data\",\"@type\":\"@json\"}}")), "\"{\\\"@direction\\\":\\\"rtl\\\",\\\"@value\\\":\\\"x\\\"}\"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON> ." },
    };

    [Theory]
    [MemberData(nameof(CarriedDocuments))]
    public void CanonicalizeJsonLd_DirectionBearingInput_CarriesTheDirectionInTheDatatype(string @case, string document, string expected)
    {
        Canonical(document).Should().Contain(expected, @case);
    }

    [Fact]
    public void CanonicalizeJsonLd_DirectionalCredential_MatchesJsonLdJsByteForByte()
    {
        // Interop pin. Expected output produced on 2026-10-30 by jsonld.js 9.0.0:
        //   jsonld.canonize(doc, { algorithm: 'RDFC-1.0', format: 'application/n-quads', safe: true,
        //                          rdfDirection: 'i18n-datatype' })
        // over the bundled credentials/v2 context, which is what jsonld-signatures and the
        // eddsa-rdfc-2022 / ecdsa-rdfc-2019 cryptosuites built on it canonize with.
        const string expected =
            "<did:example:alice> <https://schema.org/name> \"Alice\" .\n"
            + "<urn:uuid:40404040-0000-4000-8000-000000000040> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n"
            + "<urn:uuid:40404040-0000-4000-8000-000000000040> <https://schema.org/name> \"x\"^^<https://www.w3.org/ns/i18n#ar_rtl> .\n"
            + "<urn:uuid:40404040-0000-4000-8000-000000000040> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:alice> .\n"
            + "<urn:uuid:40404040-0000-4000-8000-000000000040> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer> .\n";

        Canonical(DirectionalCredential).Should().Be(expected);
    }

    [Fact]
    public void CanonicalizeJsonLd_FlippedDirection_ChangesTheCanonicalForm()
    {
        // The whole point: ≤1.4 signed these as the same bytes.
        var rtl = Canonical(Vc(Subject("\"name\":" + Directional("x", "ar", "rtl"))));
        var ltr = Canonical(Vc(Subject("\"name\":" + Directional("x", "ar", "ltr"))));
        var undirected = Canonical(Vc(Subject("\"name\":{\"@value\":\"x\",\"@language\":\"ar\"}")));

        rtl.Should().NotBe(ltr);
        rtl.Should().NotBe(undirected);
        undirected.Should().Contain("\"x\"@ar .", "a string without a direction is still a language-tagged string");
    }

    [Fact]
    public void CanonicalizeJsonLd_ExplicitI18nDatatype_IsTheSameLiteralAsTheDirectionalString()
    {
        // JSON-LD 1.1 API §8.2.2 defines the directional string's RDF form as this datatype, so the two
        // spellings are one RDF literal, as 1 and 1.0 are one xsd:integer; not a merge of distinct terms.
        var twins = Vc(Subject("\"name\":[{\"@value\":\"x\",\"@type\":\"" + I18n + "en_ltr\"}," + Directional("x", "EN", "ltr") + "]"));

        var nquads = Canonical(twins);

        nquads.Split('\n', StringSplitOptions.RemoveEmptyEntries).Count(line => line.Contains("<" + Name + ">"))
            .Should().Be(1);
        nquads.Should().Contain(Literal("x", "en", "ltr"));
    }

    [Fact]
    public void CanonicalizeJsonLd_DirectionOnANullValue_ProducesNoRdfLikeALanguageOnOne()
    {
        // A null value object produces no RDF by definition (FR-9), whatever members it carries.
        var nquads = Canonical(Vc(Subject("\"name\":\"n\",\"description\":{\"@value\":null,\"@direction\":\"rtl\"}")));

        nquads.Should().Be("<did:example:alice> <" + Name + "> \"n\" .\n<urn:uuid:40404040-0000-4000-8000-000000000040> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n<urn:uuid:40404040-0000-4000-8000-000000000040> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:alice> .\n<urn:uuid:40404040-0000-4000-8000-000000000040> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer> .\n");
    }

    [Fact]
    public void CanonicalizeJsonLd_RemoteContextDefaultDirection_Applies()
    {
        // Unlike @base, a remote context's default @language and @direction apply (JSON-LD 1.1 §4.1.2).
        var loader = new MapLoader(new Dictionary<string, string>
        {
            [MapLoader.Url] = "{\"@context\":{\"label\":\"" + Name + "\",\"@language\":\"ar\",\"@direction\":\"rtl\"}}",
        });
        var document = Parse("{\"@context\":\"" + MapLoader.Url + "\",\"@id\":\"urn:s\",\"label\":\"x\"}");

        var nquads = Encoding.UTF8.GetString(new RdfcDocumentCanonicalizer(loader).CanonicalizeJsonLd(document));

        nquads.Should().Be("<urn:s> <" + Name + "> " + Literal("x", "ar", "rtl") + " .\n");
    }

    public static TheoryData<string, string, string, string> LossyDocuments() => new()
    {
        // case, document, the message's phrase, input text the message must not quote (FR-23)
        // dotNetRDF (like jsonld.js) types a boolean or a number as an XSD literal and drops its direction
        // without a warning, with or without rdfDirection; JSON-LD 1.1 API §8.2.2 step 12 would apply the
        // i18n datatype to the lexical form instead. The refusal follows the processor.
        { "@direction on a number", Vc(Subject("\"name\":{\"@value\":7,\"@direction\":\"rtl\"}")), Direction, "rtl" },
        { "@direction on a boolean", Vc(Subject("\"name\":{\"@value\":true,\"@direction\":\"rtl\"}")), Direction, "rtl" },
        { "@direction on a double", Vc(Subject("\"name\":{\"@value\":1.5,\"@direction\":\"ltr\"}")), Direction, "ltr" },
        { "@direction on a number in a list", Vc(Subject("\"steps\":[{\"@value\":7,\"@direction\":\"rtl\"}]"), V2With("{\"steps\":{\"@id\":\"https://e.example/vocab#steps\",\"@container\":\"@list\"}}")), Direction, "rtl" },
        // With the i18n datatype a malformed tag would become a respelled datatype IRI
        // (https://www.w3.org/ns/i18n#en%0A_ltr, without a dotNetRDF warning), so the tag check runs first.
        { "malformed language tag with a direction", Vc(Subject("\"name\":" + Directional("x", "not a tag", "ltr"))), MalformedLanguageTag, "not a tag" },
        { "language tag with a trailing newline and a direction", Vc(Subject("\"name\":{\"@value\":\"x\",\"@language\":\"en\\n\",\"@direction\":\"ltr\"}")), MalformedLanguageTag, "en\n" },
        { "@index beside @direction", Vc(Subject("\"name\":{\"@value\":\"x\",\"@direction\":\"rtl\",\"@index\":\"admin\"}")), Index, "admin" },
        { "@direction on a node object", Vc(Subject("\"name\":\"n\",\"@direction\":\"rtl\"")), IgnoredContent, "rtl" },
    };

    [Theory]
    [MemberData(nameof(LossyDocuments))]
    public void CanonicalizeJsonLd_DirectionThatWouldBeDropped_ThrowsDataLossNamingTheCause(string @case, string document, string phrase, string content)
    {
        var act = () => Canonicalizer.CanonicalizeJsonLd(Parse(document));

        var ex = act.Should().Throw<JsonLdDataLossException>(@case).Which;
        ex.Message.Should().Be($"The JSON-LD input cannot be canonicalized without losing data: it {phrase}.");
        ex.Message.Should().NotContain(content);
        ex.InnerException.Should().BeNull("dotNetRDF's own messages quote the input");
    }

    public static TheoryData<string, string> InvalidDirections() => new()
    {
        // case, document. JSON-LD 1.1 expansion rejects these, so they never reach the audit.
        { "unknown direction", Vc(Subject("\"name\":" + Directional("x", "ar", "up"))) },
        { "upper-case direction", Vc(Subject("\"name\":" + Directional("x", "ar", "RTL"))) },
        { "null direction on a value object", Vc(Subject("\"name\":{\"@value\":\"x\",\"@direction\":null}")) },
        { "numeric direction", Vc(Subject("\"name\":{\"@value\":\"x\",\"@direction\":1}")) },
        { "@type beside @direction", Vc(Subject("\"name\":{\"@value\":\"x\",\"@type\":\"https://e.example/T\",\"@direction\":\"rtl\"}")) },
        { "@json beside @direction", Vc(Subject("\"name\":{\"@value\":{\"a\":1},\"@type\":\"@json\",\"@direction\":\"rtl\"}")) },
    };

    [Theory]
    [MemberData(nameof(InvalidDirections))]
    public void CanonicalizeJsonLd_InvalidDirection_FailsExpansion(string @case, string document)
    {
        var act = () => Canonicalizer.CanonicalizeJsonLd(Parse(document));

        var ex = act.Should().Throw<RdfCanonicalizationException>(@case).Which;
        ex.Should().NotBeOfType<JsonLdDataLossException>("invalid JSON-LD is a transformation error, not data loss");
        ex.Message.Should().Be("JSON-LD expansion failed.");
    }

    // ------------------------------------------------------------------ the RDFC suites

    public static TheoryData<string> Suites() => new() { EddsaRdfc2022Cryptosuite.CryptosuiteName, EcdsaRdfc2019Cryptosuite.CryptosuiteName };

    private static (ICryptosuite Suite, KeyPairSigner Signer, PublicKeyMaterial PublicKey) SuiteAndKey(string cryptosuite)
    {
        var keyType = cryptosuite == EddsaRdfc2022Cryptosuite.CryptosuiteName ? KeyType.Ed25519 : KeyType.P256;
        var keyPair = Fx.KeyGen.FromPrivateKey(keyType, Enumerable.Repeat((byte)0x40, 32).ToArray());
        ICryptosuite suite = keyType == KeyType.Ed25519 ? new EddsaRdfc2022Cryptosuite() : new EcdsaRdfc2019Cryptosuite();
        return (suite, Fx.Signer(keyPair), PublicKeyMaterial.FromRaw(keyType, keyPair.PublicKey));
    }

    private static DataIntegrityProof Options(string cryptosuite) => new()
    {
        Cryptosuite = cryptosuite,
        Created = "2026-10-30T00:00:00Z",
        VerificationMethod = "did:example:issuer#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    /// <summary>A VCDM 2.0 credential whose <c>name</c> carries a language and a base direction (§11.1).</summary>
    private static readonly string DirectionalCredential = Vc("\"name\":" + Directional("x", "ar", "rtl") + "," + Subject("\"name\":\"Alice\""));

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task CreateAndVerifyProof_DirectionBearingDocument_Succeeds(string cryptosuite)
    {
        var (suite, signer, publicKey) = SuiteAndKey(cryptosuite);

        var proof = await suite.CreateProofAsync(Parse(DirectionalCredential), Options(cryptosuite), signer);

        suite.VerifyProof(Parse(DirectionalCredential), proof, publicKey).Verified.Should().BeTrue();
    }

    public static TheoryData<string, string> DirectionTampers()
    {
        var data = new TheoryData<string, string>();
        foreach (var cryptosuite in new[] { EddsaRdfc2022Cryptosuite.CryptosuiteName, EcdsaRdfc2019Cryptosuite.CryptosuiteName })
        {
            foreach (var tamper in new[] { "flip the direction", "change the language", "remove the direction", "remove the language" })
            {
                data.Add(cryptosuite, tamper);
            }
        }

        return data;
    }

    private static JsonElement Tamper(JsonElement document, string tamper) => Fx.Mutate(document, vc =>
    {
        var name = vc["name"]!.AsObject();
        switch (tamper)
        {
            case "flip the direction":
                name["@direction"] = "ltr";
                break;
            case "change the language":
                name["@language"] = "he";
                break;
            case "remove the direction":
                name.Remove("@direction");
                break;
            case "remove the language":
                name.Remove("@language");
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(tamper), tamper, null);
        }
    });

    [Theory]
    [MemberData(nameof(DirectionTampers))]
    public async Task VerifyProof_DirectionOrLanguageChanged_Fails(string cryptosuite, string tamper)
    {
        // ≤1.4 verified the flipped and the removed direction: the direction was not in the signed bytes.
        var (suite, signer, publicKey) = SuiteAndKey(cryptosuite);
        var proof = await suite.CreateProofAsync(Parse(DirectionalCredential), Options(cryptosuite), signer);

        var result = suite.VerifyProof(Tamper(Parse(DirectionalCredential), tamper), proof, publicKey);

        result.Verified.Should().BeFalse(tamper);
        result.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.ProofVerificationError);
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task Suite_DirectionOnANumber_IsDataLoss(string cryptosuite)
    {
        var (suite, signer, publicKey) = SuiteAndKey(cryptosuite);
        var proof = await suite.CreateProofAsync(Parse(DirectionalCredential), Options(cryptosuite), signer);
        var numeric = Fx.Mutate(Parse(DirectionalCredential), vc => vc["name"] = new JsonObject { ["@value"] = 7, ["@direction"] = "rtl" });

        var verified = suite.VerifyProof(numeric, proof, publicKey);
        var create = () => suite.CreateProofAsync(numeric, Options(cryptosuite), signer);

        verified.Verified.Should().BeFalse();
        verified.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.DataLossDetectionError);
        (await create.Should().ThrowAsync<ProofGenerationException>()).WithInnerException<JsonLdDataLossException>();
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task Pipeline_DirectionBearingCredential_RoundTripsAndRejectsAFlip(string cryptosuite)
    {
        // The consumer's path: the Core pipeline over the registered RDFC suites.
        var (_, signer, publicKey) = SuiteAndKey(cryptosuite);
        var pipeline = new DataIntegrityProofPipeline(RdfcCryptosuiteRegistration.CreateWithRdfcSuites());

        var secured = await pipeline.AddProofAsync(Parse(DirectionalCredential), Options(cryptosuite), signer);
        var flipped = Tamper(secured, "flip the direction");

        pipeline.Verify(secured, publicKey).Verified.Should().BeTrue();
        var result = pipeline.Verify(flipped, publicKey);
        result.Verified.Should().BeFalse();
        result.ProofResults.Should().ContainSingle().Which.Problems.Should().ContainSingle()
            .Which.Code.Should().Be(ProofProblemCodes.ProofVerificationError);
    }

    // ------------------------------------------------------------------ bbs-2023

    [BbsFact]
    public async Task Bbs2023_DirectionBearingCredential_DerivesAndVerifies_AndRejectsAFlip()
    {
        var keyMaterial = Fx.Json("w3c", "vc-di-bbs", "TestVectors", "BBSKeyMaterial.json");
        var sk = Convert.FromHexString(keyMaterial.GetProperty("privateKeyHex").GetString()!);
        var hmacKey = Convert.FromHexString(keyMaterial.GetProperty("hmacKeyString").GetString()!);
        var publicKey = PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, Fx.KeyGen.FromPrivateKey(KeyType.Bls12381G2, sk).PublicKey);
        var suite = new Bbs2023Cryptosuite();
        var options = Options(Bbs2023Cryptosuite.CryptosuiteName) with { Type = DataIntegrityProof.DataIntegrityProofType };

        var baseProof = await suite.CreateBaseProofAsync(Parse(DirectionalCredential), options, sk, hmacKey, ["/issuer"]);
        var secured = Fx.Mutate(Parse(DirectionalCredential), vc => vc["proof"] = JsonSerializer.SerializeToNode(baseProof, DataProofsJsonOptions.Default));
        var reveal = suite.DeriveProof(secured, ["/name"], Convert.FromHexString("40404040"));

        reveal.GetProperty("name").GetProperty("@direction").GetString().Should().Be("rtl");
        VerifyReveal(suite, reveal, publicKey).Verified.Should().BeTrue();
        var flipped = VerifyReveal(suite, Tamper(reveal, "flip the direction"), publicKey);
        flipped.Verified.Should().BeFalse();
        flipped.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.ProofVerificationError);
    }

    private static ProofVerificationResult VerifyReveal(Bbs2023Cryptosuite suite, JsonElement reveal, PublicKeyMaterial publicKey)
    {
        var derivedProof = reveal.GetProperty("proof").Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
        var unsecured = Fx.Mutate(reveal, document => document.Remove("proof"));
        return suite.VerifyProof(unsecured, derivedProof, publicKey);
    }

    private sealed class MapLoader(Dictionary<string, string> contexts) : IDocumentLoader
    {
        public const string Url = "https://ctx.example/directional";

        public LoadedContextDocument Load(Uri url) => contexts.TryGetValue(url.AbsoluteUri, out var content)
            ? new LoadedContextDocument(url, content)
            : OfflineDocumentLoader.Instance.Load(url);
    }
}
