using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;
using DataProofsDotnet.Rdfc.Tests.TestSupport;
using DataProofsDotnet.Tests.Shared;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// Issue #36: RDFC canonicalization fails closed when JSON-LD processing would drop part of the
/// input or respell one of its IRIs. dotNetRDF on its own drops undefined terms and every IRI it
/// does not consider well formed (some without a warning even in safe mode), and prints IRIs
/// normalized. Whatever it dropped or respelled was not signed, so each tamper case below verified
/// before the fix. VC Data Integrity 1.0 §2.4.3 requires an error (<c>DATA_LOSS_DETECTION_ERROR</c>).
/// </summary>
public sealed class Issue36DataLossTests
{
    private const string V1 = "https://www.w3.org/2018/credentials/v1";
    private const string V2 = "https://www.w3.org/ns/credentials/v2";
    private const string UndefinedTerms = "https://www.w3.org/ns/credentials/undefined-terms/v2";

    // The canonicalizer's message phrases, asserted literally so a changed meaning fails here.
    private const string UndefinedTerm = "uses a term that its @context does not define";
    private const string MalformedIri = "has an IRI that is not a well-formed absolute IRI";
    private const string MalformedLanguageTag = "has a language tag that is not well-formed";
    private const string BlankNodeProperty = "uses a blank node as a property, which RDF cannot carry";
    private const string Direction = "uses @direction, which the canonical form does not carry";
    private const string Index = "uses @index, which the canonical form does not carry";
    private const string RespelledIri = "has an IRI that the canonical form would spell differently";
    private const string IgnoredContent = "has content that JSON-LD processing ignores";
    private const string Base = "resolves a relative IRI against @base, which the canonical form would respell";
    private const string MergedTerms = "has distinct terms that the canonical form would merge into one";
    private const string NonFiniteNumber = "has a number too large for a double, which the canonical form cannot carry";
    private const string UnpairedSurrogate = "has an unpaired UTF-16 surrogate, which UTF-8 cannot carry";

    private static readonly RdfcDocumentCanonicalizer Canonicalizer = new();

    /// <summary>A credential over <paramref name="contexts"/> whose own terms are all defined, plus <paramref name="members"/>.</summary>
    private static string Vc(string members, string contexts = "\"" + V2 + "\"")
        => "{\"@context\":[" + contexts + "],\"id\":\"urn:uuid:36363636-0000-4000-8000-000000000036\","
            + "\"type\":\"VerifiableCredential\",\"issuer\":\"did:example:issuer\"," + members + "}";

    private static string Subject(string members) => "\"credentialSubject\":{\"id\":\"did:example:alice\"," + members + "}";

    /// <summary>The credentials/v2 context followed by an inline context object.</summary>
    private static string V2With(string inlineContext) => "\"" + V2 + "\"," + inlineContext;

    private static readonly string WithUndefinedTerms = "\"" + V2 + "\",\"" + UndefinedTerms + "\"";

    // Built at run time from code points, so no tool can decode an escape into the source.
    private static readonly string Grinning = char.ConvertFromUtf32(0x1F600);
    private static readonly string Decomposed = "e" + (char)0x0301;

    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement.Clone();

    private static string Canonical(string json) => Encoding.UTF8.GetString(Canonicalizer.CanonicalizeJsonLd(Parse(json)));

    // ------------------------------------------------------------------ the canonicalizer

    public static TheoryData<string, string, string, string> LossyDocuments() => new()
    {
        // case, document, the message's phrase, input text the message must not quote (FR-23)
        { "undefined term, credentials/v2", Vc(Subject("\"clearanceLevel\":\"admin\"")), UndefinedTerm, "clearanceLevel" },
        { "undefined term, credentials/v1", "{\"@context\":\"" + V1 + "\",\"id\":\"urn:uuid:1\",\"type\":\"VerifiableCredential\",\"clearanceLevel\":\"admin\"}", UndefinedTerm, "clearanceLevel" },
        { "keyword-like member", Vc(Subject("\"@clearance\":\"admin\"")), IgnoredContent, "@clearance" },
        { "credential id with brackets", Vc(Subject("\"name\":\"n\"")).Replace("000000000036", "000000000036[0]"), MalformedIri, "[0]" },
        { "subject id with brackets", Vc("\"credentialSubject\":{\"id\":\"urn:uuid:subject[0]\",\"name\":\"n\"}"), MalformedIri, "subject[0]" },
        { "subject id with a bracketed query", Vc("\"credentialSubject\":{\"id\":\"https://e.example/users?filter[id]=alice\",\"name\":\"n\"}"), MalformedIri, "filter" },
        { "subject id with a second #", Vc("\"credentialSubject\":{\"id\":\"did:example:alice#key#extra\",\"name\":\"n\"}"), MalformedIri, "#extra" },
        { "relative subject id", Vc("\"credentialSubject\":{\"id\":\"alice\",\"name\":\"n\"}"), MalformedIri, "alice" },
        { "subject id with a space", Vc("\"credentialSubject\":{\"id\":\"did:example:al ice\",\"name\":\"n\"}"), MalformedIri, "al ice" },
        { "issuer with a bracketed query", Vc(Subject("\"name\":\"n\"")).Replace("did:example:issuer", "https://e.example/issuers?filter[id]=1"), MalformedIri, "issuers" },
        { "type with brackets", Vc(Subject("\"name\":\"n\"")).Replace("\"type\":\"VerifiableCredential\"", "\"type\":[\"VerifiableCredential\",\"Admin[0]Credential\"]"), MalformedIri, "Admin" },
        { "injected node with a malformed id", Vc("\"credentialSubject\":[{\"id\":\"did:example:alice\",\"name\":\"A\"},{\"id\":\"did:example:mallory[0]\",\"name\":\"M\"}]"), MalformedIri, "mallory" },
        { "property IRI with brackets", Vc(Subject("\"https://e.example/vocab#clearance[0]\":\"admin\"")), MalformedIri, "clearance" },
        { "term mapped to a malformed IRI", Vc(Subject("\"clearance\":\"admin\""), V2With("{\"clearance\":\"https://e.example/vocab#clearance#x\"}")), MalformedIri, "#x" },
        { "non-BMP term under undefined-terms", Vc(Subject("\"" + Grinning + "\":\"x\""), WithUndefinedTerms), MalformedIri, Grinning },
        { "blank node as a property", Vc(Subject("\"_:clearance\":\"admin\"")), BlankNodeProperty, "clearance" },
        { "named graph with a malformed name", Vc(Subject("\"name\":\"n\"") + ",\"@included\":[{\"@id\":\"urn:graph[0]\",\"@graph\":[{\"@id\":\"urn:uuid:inner\",\"name\":\"n\"}]}]"), MalformedIri, "graph" },
        { "list member with brackets", Vc(Subject("\"steps\":[\"urn:step:1\",\"urn:step[2]\"]"), V2With("{\"steps\":{\"@id\":\"https://e.example/vocab#steps\",\"@type\":\"@id\",\"@container\":\"@list\"}}")), MalformedIri, "step[2]" },
        { "@direction", Vc(Subject("\"name\":{\"@value\":\"x\",\"@language\":\"ar\",\"@direction\":\"rtl\"}")), Direction, "rtl" },
        { "malformed language tag", Vc(Subject("\"name\":{\"@value\":\"x\",\"@language\":\"not a tag\"}")), MalformedLanguageTag, "not a tag" },
        { "@index map key", Vc(Subject("\"notes\":{\"first\":\"a\"}"), V2With("{\"notes\":{\"@id\":\"https://e.example/vocab#notes\",\"@container\":\"@index\"}}")), Index, "first" },
        { "respelled: %2E%2E segment", Vc("\"credentialSubject\":{\"id\":\"https://e.example/x/%2E%2E/users/alice\",\"name\":\"n\"}"), RespelledIri, "%2E" },
        { "respelled: .. segment", Vc("\"credentialSubject\":{\"id\":\"https://e.example/x/../users/alice\",\"name\":\"n\"}"), RespelledIri, "/x/" },
        { "respelled: . segment", Vc("\"credentialSubject\":{\"id\":\"https://e.example/./users/alice\",\"name\":\"n\"}"), RespelledIri, "/./" },
        { "respelled: unreserved escape", Vc("\"credentialSubject\":{\"id\":\"https://e.example/users/%61lice\",\"name\":\"n\"}"), RespelledIri, "%61" },
        { "respelled: non-ASCII escape", Vc("\"credentialSubject\":{\"id\":\"https://e.example/users/caf%C3%A9\",\"name\":\"n\"}"), RespelledIri, "%C3" },
        { "respelled: trailing soft hyphen", Vc("\"credentialSubject\":{\"id\":\"https://e.example/7/%C2%AD\",\"name\":\"n\"}"), RespelledIri, "%C2" },
        { "respelled: upper-case scheme and host", Vc("\"credentialSubject\":{\"id\":\"HTTPS://E.EXAMPLE/users/alice\",\"name\":\"n\"}"), RespelledIri, "E.EXAMPLE" },
        { "respelled: default port", Vc("\"credentialSubject\":{\"id\":\"https://e.example:443/users/alice\",\"name\":\"n\"}"), RespelledIri, ":443" },
        { "respelled: fragment escape", Vc("\"credentialSubject\":{\"id\":\"https://e.example/users#%61lice\",\"name\":\"n\"}"), RespelledIri, "%61" },
        { "respelled: query escape", Vc("\"credentialSubject\":{\"id\":\"https://e.example/users?q=%7e\",\"name\":\"n\"}"), RespelledIri, "%7e" },
        // dotNetRDF resolves against @base with System.Uri, so "users/%61lice" would sign as
        // <https://e.example/users/alice>, the same as "users/alice" (adversarial review, B1).
        { "@base respelling a relative IRI", "{\"@context\":{\"@base\":\"https://e.example/\",\"name\":\"https://schema.org/name\"},\"@id\":\"users/%61lice\",\"name\":\"n\"}", Base, "%61lice" },
        { "@base in a scoped context", Vc(Subject("\"knows\":{\"id\":\"users/%61lice\"}"), V2With("{\"knows\":{\"@id\":\"https://schema.org/knows\",\"@context\":{\"@base\":\"https://e.example/\"}}}")), Base, "%61lice" },
        // dotNetRDF's node equality compares parsed URI components, so the store would hold one
        // subject (or datatype) for two distinct RDF IRIs and drop the second's statements (PR #37 review).
        { "subjects differing only by an empty path", Vc("\"credentialSubject\":[{\"id\":\"https://e.example\",\"name\":\"A\"},{\"id\":\"https://e.example/\",\"name\":\"A\"}]"), MergedTerms, "e.example" },
        // The store also looks graphs up by that equality: the second graph's statements would be printed
        // under the first graph's name (adversarial review, F2).
        { "graph names differing only by an empty path", Vc(Subject("\"name\":\"n\",\"@included\":[{\"@id\":\"https://g.example\",\"@graph\":[{\"@id\":\"urn:a\",\"name\":\"1\"}]},{\"@id\":\"https://g.example/\",\"@graph\":[{\"@id\":\"urn:b\",\"name\":\"2\"}]}]")), MergedTerms, "g.example" },
        // dotNetRDF's language-tag pattern ends in $, which also matches before a final newline (F3).
        { "language tag with a trailing newline", Vc(Subject("\"name\":{\"@value\":\"x\",\"@language\":\"en\\n\"}")), MalformedLanguageTag, "en\n" },
        { "default language with a trailing newline", Vc(Subject("\"name\":\"x\""), V2With("{\"@language\":\"en\\n\"}")), MalformedLanguageTag, "en\n" },
        // Newtonsoft reads both as an infinity, so they would sign as one "Infinity" (F5).
        { "numbers beyond the double range", Vc(Subject("\"rank\":[1e400,2e400]"), WithUndefinedTerms), NonFiniteNumber, "1e400" },
        { "number beyond the double range in @json", Vc(Subject("\"data\":{\"a\":1e400}"), V2With("{\"data\":{\"@id\":\"https://e.example/vocab#data\",\"@type\":\"@json\"}}")), NonFiniteNumber, "1e400" },
        { "datatypes differing only by an empty path", Vc(Subject("\"name\":[{\"@value\":\"x\",\"@type\":\"https://e.example\"},{\"@value\":\"x\",\"@type\":\"https://e.example/\"}]")), MergedTerms, "e.example" },
        { "respelled datatype IRI", Vc(Subject("\"name\":{\"@value\":\"x\",\"@type\":\"https://e.example/x/../datatype\"}")), RespelledIri, "datatype" },
    };

    [Theory]
    [MemberData(nameof(LossyDocuments))]
    public void CanonicalizeJsonLd_LossyInput_ThrowsDataLossNamingTheCause(string @case, string document, string phrase, string content)
    {
        var act = () => Canonicalizer.CanonicalizeJsonLd(Parse(document));

        var ex = act.Should().Throw<JsonLdDataLossException>(@case).Which;
        ex.Message.Should().Be($"The JSON-LD input cannot be canonicalized without losing data: it {phrase}.");
        ex.Message.Should().NotContain(content);
        ex.InnerException.Should().BeNull("dotNetRDF's own messages quote the input");
    }

    public static TheoryData<string, string, string> CarriedDocuments() => new()
    {
        // case, document, an N-Quads fragment the output must contain verbatim
        { "plain credential", Vc(Subject("\"name\":\"Alice\"")), "<did:example:alice> <https://schema.org/name> \"Alice\" ." },
        { "host-only URL", Vc(Subject("\"name\":\"n\"")).Replace("did:example:issuer", "https://issuer.example"), "<https://issuer.example> ." },
        { "IDN host", Vc("\"credentialSubject\":{\"id\":\"https://café.example/x\",\"name\":\"n\"}"), "<https://café.example/x>" },
        { "percent-encoded space and slash", Vc("\"credentialSubject\":{\"id\":\"https://e.example/a%20b/c%2Fd\",\"name\":\"n\"}"), "<https://e.example/a%20b/c%2Fd>" },
        { "query string", Vc("\"credentialSubject\":{\"id\":\"https://e.example/a?x=1&y=2\",\"name\":\"n\"}"), "<https://e.example/a?x=1&y=2>" },
        { "zcap root id", Vc("\"credentialSubject\":{\"id\":\"urn:zcap:root:https%3A%2F%2Fapi.example%2Fitems\",\"name\":\"n\"}"), "<urn:zcap:root:https%3A%2F%2Fapi.example%2Fitems>" },
        { "DID URL with a fragment", Vc("\"credentialSubject\":{\"id\":\"did:example:123#key-1\",\"name\":\"n\"}"), "<did:example:123#key-1>" },
        { "did:web with an encoded port", Vc("\"credentialSubject\":{\"id\":\"did:web:example.com%3A8443\",\"name\":\"n\"}"), "<did:web:example.com%3A8443>" },
        { "undefined terms under undefined-terms/v2", Vc(Subject("\"clearanceLevel\":\"admin\""), WithUndefinedTerms), "<https://www.w3.org/ns/credentials/undefined-term#clearanceLevel> \"admin\"" },
        { "BMP non-ASCII term under undefined-terms/v2", Vc(Subject("\"café\":\"x\""), WithUndefinedTerms), "<https://www.w3.org/ns/credentials/undefined-term#café>" },
        { "language-tagged string", Vc(Subject("\"name\":{\"@value\":\"x\",\"@language\":\"en-US\"}")), "\"x\"@en-us" },
        { "@json literal", Vc(Subject("\"data\":{\"a\":[1,2]}"), V2With("{\"data\":{\"@id\":\"https://e.example/vocab#data\",\"@type\":\"@json\"}}")), "\"{\\\"a\\\":[1,2]}\"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON>" },
        { "null value", Vc(Subject("\"name\":\"n\",\"description\":null")), "<did:example:alice> <https://schema.org/name> \"n\" ." },
        { "blank-node subject", Vc("\"credentialSubject\":{\"name\":\"n\"}"), "_:c14n0 <https://schema.org/name> \"n\" ." },
        { "@base: null", Vc(Subject("\"name\":\"n\""), V2With("{\"@base\":null}")), "<did:example:alice> <https://schema.org/name> \"n\" ." },
        { "@base that resolves nothing", Vc(Subject("\"name\":\"n\""), V2With("{\"@base\":\"https://e.example/\"}")), "<did:example:alice> <https://schema.org/name> \"n\" ." },
        { "@json term whose payload holds a @base key", Vc(Subject("\"data\":{\"@base\":\"ordinary application data\"}"), V2With("{\"data\":{\"@id\":\"https://e.example/vocab#data\",\"@type\":\"@json\"}}")), "<https://e.example/vocab#data> \"{\\\"@base\\\":\\\"ordinary application data\\\"}\"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON> ." },
        { "@json value object whose payload holds a @base key", Vc(Subject("\"data\":{\"@value\":{\"@base\":\"x\"},\"@type\":\"@json\"}"), V2With("{\"data\":\"https://e.example/vocab#data\"}")), "<https://e.example/vocab#data> \"{\\\"@base\\\":\\\"x\\\"}\"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON> ." },
        { "IRIs differing by an empty query or fragment", Vc("\"credentialSubject\":[{\"id\":\"https://e.example/a?\",\"name\":\"A\"},{\"id\":\"https://e.example/a#\",\"name\":\"A\"}]"), "<https://e.example/a#> <https://schema.org/name> \"A\" .\n<https://e.example/a?> <https://schema.org/name> \"A\" ." },
        // Literal values are not Unicode-normalized: a decomposed é is signed as written.
        { "decomposed (NFD) literal", Vc(Subject("\"name\":\"" + Decomposed + "\"")), "<https://schema.org/name> \"" + Decomposed + "\" ." },
    };

    [Theory]
    [MemberData(nameof(CarriedDocuments))]
    public void CanonicalizeJsonLd_LosslessInput_KeepsEveryIriAsWritten(string @case, string document, string expected)
    {
        Canonical(document).Should().Contain(expected, @case);
    }

    [Fact]
    public void CanonicalizeNQuads_RespelledIri_Throws()
    {
        const string respelled = "<https://e.example/x/../b> <https://e.example/p> \"o\" .\n";
        const string exact = "<https://e.example/b> <https://e.example/p> \"o\" .\n";

        var canonicalize = () => Canonicalizer.CanonicalizeNQuads(respelled);
        var map = () => Canonicalizer.CanonicalizeNQuadsToMap(respelled);

        canonicalize.Should().Throw<RdfCanonicalizationException>()
            .WithMessage($"The N-Quads input cannot be canonicalized as written: it {RespelledIri}.");
        map.Should().Throw<RdfCanonicalizationException>();
        Canonicalizer.CanonicalizeNQuads(exact).Should().Be(exact);
    }

    [Fact]
    public void CanonicalizeJsonLd_JsonWhoseMeaningIsUnpredictable_Throws()
    {
        // The suites check this before calling, but the canonicalizer is public API (adversarial
        // review, F4): an unpaired surrogate read as U+FFFD, or a duplicate member of which the last wins.
        var surrogate = "{\"@context\":\"" + V2 + "\",\"@id\":\"urn:s\",\"name\":\"a" + HostileJson.LoneEscape("DC00") + "b\"}";
        var duplicate = "{\"@context\":\"" + V2 + "\",\"@id\":\"urn:s\",\"name\":\"Alice\",\"name\":\"Mallory\"}";
        var duplicateContext = "{\"@context\":\"" + V2 + "\",\"@context\":{\"name\":\"https://evil.example/name\"},\"@id\":\"urn:s\",\"name\":\"x\"}";

        foreach (var (json, problem) in new[]
        {
            (surrogate, HostileJson.Surrogate), (duplicate, HostileJson.Duplicate), (duplicateContext, HostileJson.Duplicate),
        })
        {
            var act = () => Canonicalizer.CanonicalizeJsonLd(HostileJson.Parse(json));
            act.Should().Throw<RdfCanonicalizationException>().WithMessage($"The JSON-LD input {problem}.");
        }
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task VerifyProof_DuplicateMemberCalledDirectly_IsTransformationError(string cryptosuite)
    {
        // Through the pipeline this was already a document-level PROOF_TRANSFORMATION_ERROR (issue #33);
        // calling the suite directly reached the canonicalizer, which let the last duplicate win.
        var (suite, signer, publicKey) = SuiteAndKey(cryptosuite);
        var proof = await suite.CreateProofAsync(Parse(Signed), Options(cryptosuite), signer);
        var duplicated = HostileJson.Parse(HostileJson.LastMember(Signed, "\"issuer\":\"did:example:mallory\""));

        var result = suite.VerifyProof(duplicated, proof, publicKey);

        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.ProofTransformationError);
    }

    [Fact]
    public void CanonicalizeNQuads_UnpairedSurrogateEscape_Throws()
    {
        // UTF-8 output would carry it as U+FFFD, the same bytes as a real U+FFFD (F4).
        var lone = "<urn:s> <urn:p> \"a" + HostileJson.Esc(0xDC00) + "b\" .\n";

        var act = () => Canonicalizer.CanonicalizeNQuads(lone);

        act.Should().Throw<RdfCanonicalizationException>()
            .WithMessage($"The N-Quads input cannot be canonicalized as written: it {UnpairedSurrogate}.");
        Canonicalizer.CanonicalizeNQuads("<urn:s> <urn:p> \"a" + HostileJson.Esc(0xFFFD) + "b\" .\n").Should().NotBeEmpty();
    }

    [Fact]
    public void CanonicalizeJsonLd_ScopedBaseInARemoteContext_Throws()
    {
        // dotNetRDF ignores a remote context's own @base but honors one in a scoped context it defines,
        // so "users/%61lice" signed as "users/alice" (adversarial review, F1).
        var loader = new MapLoader(new Dictionary<string, string>
        {
            [MapLoader.Url] = "{\"@context\":{\"label\":\"https://schema.org/name\","
                + "\"friend\":{\"@id\":\"https://schema.org/knows\",\"@context\":{\"@base\":\"https://e.example/\"}},"
                + "\"Person\":{\"@id\":\"https://schema.org/Person\",\"@context\":{\"@base\":\"https://e.example/\"}}}}",
        });
        var canonicalizer = new RdfcDocumentCanonicalizer(loader);
        var propertyScoped = Parse("{\"@context\":\"" + MapLoader.Url + "\",\"@id\":\"urn:s\",\"friend\":{\"@id\":\"users/%61lice\",\"label\":\"A\"}}");
        var typeScoped = Parse("{\"@context\":\"" + MapLoader.Url + "\",\"@id\":\"users/%61lice\",\"@type\":\"Person\",\"label\":\"A\"}");

        foreach (var document in new[] { propertyScoped, typeScoped })
        {
            var act = () => canonicalizer.CanonicalizeJsonLd(document);
            act.Should().Throw<JsonLdDataLossException>()
                .WithMessage($"The JSON-LD input cannot be canonicalized without losing data: it {Base}.");
        }
    }

    [Fact]
    public void CanonicalizeJsonLd_RemoteContextsOwnBase_ResolvesNothing()
    {
        // JSON-LD 1.1 ignores a remote context's own @base, so nothing is resolved and nothing refused.
        var loader = new MapLoader(new Dictionary<string, string>
        {
            [MapLoader.Url] = "{\"@context\":{\"@base\":\"https://e.example/\",\"label\":\"https://schema.org/name\"}}",
        });
        var document = Parse("{\"@context\":\"" + MapLoader.Url + "\",\"@id\":\"https://e.example/users/alice\",\"label\":\"A\"}");

        var nquads = Encoding.UTF8.GetString(new RdfcDocumentCanonicalizer(loader).CanonicalizeJsonLd(document));

        nquads.Should().Be("<https://e.example/users/alice> <https://schema.org/name> \"A\" .\n");
    }

    [Fact]
    public void CanonicalizeNQuads_DistinctTermsTheStoreWouldMerge_Throws()
    {
        const string merged = "<https://e.example> <urn:p> <urn:o> .\n<https://e.example/> <urn:p> <urn:o> .\n";
        const string duplicate = "<https://e.example> <urn:p> <urn:o> .\n<https://e.example> <urn:p> <urn:o> .\n";
        const string twoStatements = "<https://e.example> <urn:p> <urn:o> .\n<https://e.example/> <urn:q> <urn:o> .\n";

        var canonicalize = () => Canonicalizer.CanonicalizeNQuads(merged);

        canonicalize.Should().Throw<RdfCanonicalizationException>()
            .WithMessage($"The N-Quads input cannot be canonicalized as written: it {MergedTerms}.");

        // Graph names: the statements stay distinct, but the second would be printed in the first's graph (F2).
        foreach (var graphs in new[]
        {
            "<urn:a> <urn:p> \"1\" <https://g.example> .\n<urn:b> <urn:p> \"2\" <https://g.example/> .\n",
            "<urn:b> <urn:p> \"2\" <https://g.example/> .\n<urn:a> <urn:p> \"1\" <https://g.example> .\n",
        })
        {
            var graphMerge = () => Canonicalizer.CanonicalizeNQuads(graphs);
            graphMerge.Should().Throw<RdfCanonicalizationException>().WithMessage($"*it {MergedTerms}.");
        }

        Canonicalizer.CanonicalizeNQuads(duplicate).Should().Be("<https://e.example> <urn:p> <urn:o> .\n", "an exact duplicate is the same RDF statement");
        Canonicalizer.CanonicalizeNQuads(twoStatements).Should().Be(
            "<https://e.example/> <urn:q> <urn:o> .\n<https://e.example> <urn:p> <urn:o> .\n", "each statement keeps its own spelling");
    }

    [Fact]
    public void CanonicalizeJsonLd_LoaderThatChangesItsAnswer_IsReadOncePerCanonicalization()
    {
        // The audit and the parse expand separately. If each loaded the context itself, the second
        // answer here (a term mapped to an IRI dotNetRDF drops without a warning) would reach only
        // the parse, and the property would vanish from the signed bytes unnoticed.
        var loader = new ChangingLoader(
            "{\"@context\":{\"clearance\":\"https://e.example/vocab#clearance\"}}",
            "{\"@context\":{\"clearance\":\"https://e.example/vocab#clearance#dropped\"}}");
        var canonicalizer = new RdfcDocumentCanonicalizer(loader);
        var document = Parse("{\"@context\":\"" + ChangingLoader.Url + "\",\"@id\":\"did:example:alice\",\"clearance\":\"admin\"}");

        var nquads = Encoding.UTF8.GetString(canonicalizer.CanonicalizeJsonLd(document));

        nquads.Should().Be("<did:example:alice> <https://e.example/vocab#clearance> \"admin\" .\n");
        loader.Loads.Should().Be(1);
    }

    [Fact]
    public void CanonicalizeJsonLd_Import_FailsClosed()
    {
        // @import merges a remote context into a local one, so it could carry a @base along, which the
        // input check cannot see. dotNetRDF fails on @import while the base is null; if an upgrade
        // makes it work, this fails and the remote @base needs the input check's treatment.
        var canonicalizer = new RdfcDocumentCanonicalizer(new ChangingLoader(
            "{\"@context\":{\"@base\":\"https://e.example/\"}}", "{\"@context\":{\"@base\":\"https://e.example/\"}}"));
        var document = Parse("{\"@context\":{\"@version\":1.1,\"@import\":\"" + ChangingLoader.Url + "\",\"name\":\"https://schema.org/name\"},"
            + "\"@id\":\"users/%61lice\",\"name\":\"n\"}");

        var act = () => canonicalizer.CanonicalizeJsonLd(document);

        act.Should().Throw<RdfCanonicalizationException>();
    }

    private sealed class MapLoader(Dictionary<string, string> contexts) : IDocumentLoader
    {
        public const string Url = "https://ctx.example/friends";

        public LoadedContextDocument Load(Uri url) => contexts.TryGetValue(url.AbsoluteUri, out var content)
            ? new LoadedContextDocument(url, content)
            : OfflineDocumentLoader.Instance.Load(url);
    }

    private sealed class ChangingLoader(string first, string later) : IDocumentLoader
    {
        public const string Url = "https://e.example/contexts/changing";

        public int Loads { get; private set; }

        public LoadedContextDocument Load(Uri url)
        {
            Loads++;
            return new LoadedContextDocument(url, Loads == 1 ? first : later);
        }
    }

    // ------------------------------------------------------------------ the RDFC suites

    public static TheoryData<string> Suites() => new() { EddsaRdfc2022Cryptosuite.CryptosuiteName, EcdsaRdfc2019Cryptosuite.CryptosuiteName };

    private static (ICryptosuite Suite, ISigner Signer, PublicKeyMaterial PublicKey) SuiteAndKey(string cryptosuite)
    {
        var keyType = cryptosuite == EddsaRdfc2022Cryptosuite.CryptosuiteName ? KeyType.Ed25519 : KeyType.P256;
        var keyPair = Fx.KeyGen.FromPrivateKey(keyType, Enumerable.Repeat((byte)0x36, 32).ToArray());
        ICryptosuite suite = keyType == KeyType.Ed25519 ? new EddsaRdfc2022Cryptosuite() : new EcdsaRdfc2019Cryptosuite();
        return (suite, Fx.Signer(keyPair), PublicKeyMaterial.FromRaw(keyType, keyPair.PublicKey));
    }

    private static DataIntegrityProof Options(string cryptosuite) => new()
    {
        Cryptosuite = cryptosuite,
        Created = "2026-10-28T00:00:00Z",
        VerificationMethod = "did:example:issuer#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    private static readonly string Signed = Vc(Subject("\"name\":\"Alice\"")).Replace("did:example:issuer", "https://issuer.example/i")
        .Replace("did:example:alice", "https://e.example/users/alice");

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task CreateProof_LossyDocument_ThrowsProofGenerationException(string cryptosuite)
    {
        var (suite, signer, _) = SuiteAndKey(cryptosuite);

        var act = () => suite.CreateProofAsync(Parse(Vc(Subject("\"clearanceLevel\":\"admin\""))), Options(cryptosuite), signer);

        (await act.Should().ThrowAsync<ProofGenerationException>())
            .WithMessage("*cannot be RDFC-canonicalized without losing data*")
            .WithInnerException<JsonLdDataLossException>();
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task CreateProof_ProofOptionTheContextDoesNotDefine_ThrowsProofGenerationException(string cryptosuite)
    {
        var (suite, signer, _) = SuiteAndKey(cryptosuite);
        var options = Options(cryptosuite) with
        {
            AdditionalProperties = new Dictionary<string, JsonElement> { ["capabilityChain"] = Parse("[\"urn:zcap:root:x\"]") },
        };

        var act = () => suite.CreateProofAsync(Parse(Signed), options, signer);

        (await act.Should().ThrowAsync<ProofGenerationException>()).WithInnerException<JsonLdDataLossException>();
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task CreateProof_CredentialsV1Alone_RefusesTheProofConfiguration(string cryptosuite)
    {
        // credentials/v1 defines the credential but not DataIntegrityProof, so the configuration's
        // cryptosuite, purpose and method would go unsigned; data-integrity/v2 defines them.
        var (suite, signer, publicKey) = SuiteAndKey(cryptosuite);
        const string credential = ",\"id\":\"urn:uuid:1\",\"type\":[\"VerifiableCredential\"],\"issuer\":\"did:example:issuer\","
            + "\"issuanceDate\":\"2026-01-01T00:00:00Z\",\"credentialSubject\":{\"id\":\"did:example:alice\"}}";
        var v1Only = Parse("{\"@context\":[\"" + V1 + "\"]" + credential);
        var withDataIntegrity = Parse("{\"@context\":[\"" + V1 + "\",\"https://w3id.org/security/data-integrity/v2\"]" + credential);

        var act = () => suite.CreateProofAsync(v1Only, Options(cryptosuite), signer);

        (await act.Should().ThrowAsync<ProofGenerationException>()).WithInnerException<JsonLdDataLossException>();
        var proof = await suite.CreateProofAsync(withDataIntegrity, Options(cryptosuite), signer);
        suite.VerifyProof(withDataIntegrity, proof, publicKey).Verified.Should().BeTrue();
    }

    public static TheoryData<string, string> Tampers()
    {
        // Each of these verified against a proof over Signed before issue #36.
        var data = new TheoryData<string, string>();
        foreach (var cryptosuite in new[] { EddsaRdfc2022Cryptosuite.CryptosuiteName, EcdsaRdfc2019Cryptosuite.CryptosuiteName })
        {
            foreach (var tamper in new[]
            {
                "add an undefined claim", "inject a second subject", "inject a refreshService", "append a type",
                "inject a nested node", "respell the subject id", "respell the issuer",
            })
            {
                data.Add(cryptosuite, tamper);
            }
        }

        return data;
    }

    private static JsonElement Tamper(JsonElement document, string tamper) => Fx.Mutate(document, vc =>
    {
        switch (tamper)
        {
            case "add an undefined claim":
                vc["credentialSubject"]!["clearanceLevel"] = "admin";
                break;
            case "inject a second subject":
                vc["credentialSubject"] = new JsonArray(
                    vc["credentialSubject"]!.DeepClone(),
                    new JsonObject { ["id"] = "did:example:mallory[0]", ["name"] = "Mallory" });
                break;
            case "inject a refreshService":
                vc["refreshService"] = new JsonObject { ["id"] = "https://evil.example/r?u[0]=1", ["type"] = "RefreshService" };
                break;
            case "append a type":
                vc["type"] = new JsonArray("VerifiableCredential", "Admin[0]Credential");
                break;
            case "inject a nested node":
                vc["credentialSubject"]!["knows"] = new JsonObject { ["id"] = "https://org.example/g?x[0]", ["name"] = "admins" };
                break;
            case "respell the subject id":
                vc["credentialSubject"]!["id"] = "https://e.example/x/%2E%2E/users/alice";
                break;
            case "respell the issuer":
                vc["issuer"] = "HTTPS://ISSUER.EXAMPLE/i";
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(tamper), tamper, null);
        }
    });

    [Theory]
    [MemberData(nameof(Tampers))]
    public async Task VerifyProof_TamperThatCanonicalizationWouldDrop_IsDataLossDetectionError(string cryptosuite, string tamper)
    {
        var (suite, signer, publicKey) = SuiteAndKey(cryptosuite);
        var proof = await suite.CreateProofAsync(Parse(Signed), Options(cryptosuite), signer);

        suite.VerifyProof(Parse(Signed), proof, publicKey).Verified.Should().BeTrue();

        var result = suite.VerifyProof(Tamper(Parse(Signed), tamper), proof, publicKey);
        result.Verified.Should().BeFalse(tamper);
        result.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.DataLossDetectionError);
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task VerifyProof_SubjectTheStoreWouldMergeWithASignedOne_IsDataLossDetectionError(string cryptosuite)
    {
        // PR #37 review, P1: before the fix, appending the trailing-slash subject still verified.
        var (suite, signer, publicKey) = SuiteAndKey(cryptosuite);
        var document = Parse(Vc("\"credentialSubject\":[{\"id\":\"https://e.example\",\"name\":\"Alice\"}]"));
        var proof = await suite.CreateProofAsync(document, Options(cryptosuite), signer);

        JsonElement Append(string id) => Fx.Mutate(document, vc =>
            ((JsonArray)vc["credentialSubject"]!).Add(new JsonObject { ["id"] = id, ["name"] = "Alice" }));

        var merged = suite.VerifyProof(Append("https://e.example/"), proof, publicKey);
        merged.Verified.Should().BeFalse();
        merged.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.DataLossDetectionError);

        var added = suite.VerifyProof(Append("https://e.example/other"), proof, publicKey);
        added.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.ProofVerificationError, "an ordinary extra statement breaks the signature");

        suite.VerifyProof(Append("https://e.example"), proof, publicKey).Verified
            .Should().BeTrue("an exact duplicate adds no RDF statement");
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task VerifyProof_StatementMovedIntoAGraphTheStoreWouldMerge_IsDataLossDetectionError(string cryptosuite)
    {
        // Adversarial review, F2: moving urn:b into graph https://g.example/ still verified.
        var (suite, signer, publicKey) = SuiteAndKey(cryptosuite);
        string WithGraphs(string graphs) => Vc(Subject("\"name\":\"n\",\"@included\":[" + graphs + "]"));
        const string a = "{\"@id\":\"urn:a\",\"name\":\"1\"}";
        const string b = "{\"@id\":\"urn:b\",\"name\":\"2\"}";
        var signed = Parse(WithGraphs("{\"@id\":\"https://g.example\",\"@graph\":[" + a + "," + b + "]}"));
        var proof = await suite.CreateProofAsync(signed, Options(cryptosuite), signer);

        var moved = suite.VerifyProof(
            Parse(WithGraphs("{\"@id\":\"https://g.example\",\"@graph\":[" + a + "]},{\"@id\":\"https://g.example/\",\"@graph\":[" + b + "]}")),
            proof, publicKey);
        moved.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.DataLossDetectionError);

        var elsewhere = suite.VerifyProof(
            Parse(WithGraphs("{\"@id\":\"https://g.example\",\"@graph\":[" + a + "]},{\"@id\":\"https://h.example/\",\"@graph\":[" + b + "]}")),
            proof, publicKey);
        elsewhere.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.ProofVerificationError, "a real move is a signature failure");
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task JsonLiteralHoldingABaseKey_IsSignedVerbatim(string cryptosuite)
    {
        // PR #37 review, P2: a "@base" key inside a JSON literal is data, not a context.
        var (suite, signer, publicKey) = SuiteAndKey(cryptosuite);
        var document = Parse(Vc(
            Subject("\"data\":{\"@base\":\"ordinary application data\"}"),
            V2With("{\"data\":{\"@id\":\"https://e.example/vocab#data\",\"@type\":\"@json\"}}")));
        var proof = await suite.CreateProofAsync(document, Options(cryptosuite), signer);

        suite.VerifyProof(document, proof, publicKey).Verified.Should().BeTrue();

        var tampered = Fx.Mutate(document, vc => vc["credentialSubject"]!["data"]!["@base"] = "other application data");
        suite.VerifyProof(tampered, proof, publicKey).Problems
            .Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.ProofVerificationError, "the literal is signed");
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task Pipeline_Verify_PassesTheDataLossCodeThrough(string cryptosuite)
    {
        var (_, signer, publicKey) = SuiteAndKey(cryptosuite);
        var pipeline = new DataIntegrityProofPipeline(RdfcCryptosuiteRegistration.CreateWithRdfcSuites());
        var secured = await pipeline.AddProofAsync(Parse(Signed), Options(cryptosuite), signer);

        var result = pipeline.Verify(Tamper(secured, "add an undefined claim"), publicKey);

        result.Verified.Should().BeFalse();
        result.ProofResults.Should().ContainSingle().Which.Problems
            .Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.DataLossDetectionError);
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task UndefinedTermsContext_SignsTheClaim_SoTamperingItBreaksTheSignature(string cryptosuite)
    {
        // VCDM 2.0 §5.2: the sanctioned way to sign terms no context defines.
        var (suite, signer, publicKey) = SuiteAndKey(cryptosuite);
        var document = Parse(Vc(Subject("\"clearanceLevel\":\"viewer\""), WithUndefinedTerms));
        var proof = await suite.CreateProofAsync(document, Options(cryptosuite), signer);

        suite.VerifyProof(document, proof, publicKey).Verified.Should().BeTrue();

        var result = suite.VerifyProof(Fx.Mutate(document, vc => vc["credentialSubject"]!["clearanceLevel"] = "admin"), proof, publicKey);
        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.ProofVerificationError);
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task ChangingASignedValue_IsStillASignatureFailure(string cryptosuite)
    {
        var (suite, signer, publicKey) = SuiteAndKey(cryptosuite);
        var proof = await suite.CreateProofAsync(Parse(Signed), Options(cryptosuite), signer);

        var result = suite.VerifyProof(Fx.Mutate(Parse(Signed), vc => vc["credentialSubject"]!["name"] = "Mallory"), proof, publicKey);

        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.ProofVerificationError);
    }

    // ------------------------------------------------------------------ bbs-2023

    private static (byte[] Sk, byte[] HmacKey) BbsKeyMaterial()
    {
        var keyMat = Fx.Json("w3c", "vc-di-bbs", "TestVectors", "BBSKeyMaterial.json");
        return (
            Convert.FromHexString(keyMat.GetProperty("privateKeyHex").GetString()!),
            Convert.FromHexString(keyMat.GetProperty("hmacKeyString").GetString()!));
    }

    private static DataIntegrityProof BbsOptions() => new()
    {
        Type = DataIntegrityProof.DataIntegrityProofType,
        Cryptosuite = Bbs2023Cryptosuite.CryptosuiteName,
        Created = "2023-08-15T23:36:38Z",
        VerificationMethod = "did:key:zUC7Derd#zUC7Derd",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    private static JsonElement WindDoc() => Fx.Json("w3c", "vc-di-bbs", "TestVectors", "windDoc.json");

    private static string[] WindMandatory()
        => JsonSerializer.Deserialize<string[]>(Fx.Text("w3c", "vc-di-bbs", "TestVectors", "windMandatory.json"))!;

    [BbsFact]
    public async Task Bbs2023_CreateBaseProof_LossyDocument_ThrowsProofGenerationException()
    {
        var (sk, hmacKey) = BbsKeyMaterial();
        var lossy = Fx.Mutate(WindDoc(), vc => vc["credentialSubject"]!["id"] = "urn:uuid:sailor[0]");

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(lossy, BbsOptions(), sk, hmacKey, WindMandatory());

        (await act.Should().ThrowAsync<ProofGenerationException>())
            .WithMessage("*cannot be RDFC-canonicalized without losing data*")
            .WithInnerException<JsonLdDataLossException>();
    }

    // bbs-2023 relabeled blank nodes and deskolemized by rewriting text across whole N-Quad lines, so a
    // literal holding "<urn:bnid:_:b0>" was signed as "_:b0": a holder could swap one for the other
    // and still verify, and a literal holding "_:c14n0" did not verify at all (adversarial review).
    [BbsTheory]
    [InlineData("<urn:bnid:_:b0>", "_:b0")]
    [InlineData("_:b0", "_:b1")]
    [InlineData("_:c14n0", "_:c14n1")]
    public async Task Bbs2023_LiteralHoldingLabelText_IsSignedAsWritten(string note, string swapped)
    {
        var (sk, hmacKey) = BbsKeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var document = Fx.Mutate(WindDoc(), vc => vc["credentialSubject"]!["note"] = note);
        var baseProof = await suite.CreateBaseProofAsync(document, BbsOptions(), sk, hmacKey, WindMandatory());
        var secured = Fx.Mutate(document, vc => vc["proof"] = JsonSerializer.SerializeToNode(baseProof, DataProofsJsonOptions.Default));
        var reveal = suite.DeriveProof(secured, ["/credentialSubject/note"], Convert.FromHexString("113377aa"));
        var derivedProof = reveal.GetProperty("proof").Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
        var pk = PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, Fx.KeyGen.FromPrivateKey(KeyType.Bls12381G2, sk).PublicKey);
        var unsecured = Fx.Mutate(reveal, vc => vc.Remove("proof"));

        suite.VerifyProof(unsecured, derivedProof, pk).Verified.Should().BeTrue();
        suite.VerifyProof(Fx.Mutate(unsecured, vc => vc["credentialSubject"]!["note"] = swapped), derivedProof, pk)
            .Verified.Should().BeFalse("the literal is signed as written");
    }

    // Skolem ids are urn:bnid: IRIs read back as blank nodes, so an issuer's own IRI there would be too.
    [BbsTheory]
    [InlineData("\"id\":\"urn:bnid:_:b0\"")]
    [InlineData("\"id\":\"bn:_:b0\"")]
    public async Task Bbs2023_CreateBaseProof_DocumentUsingTheSkolemNamespace_ThrowsProofGenerationException(string member)
    {
        var (sk, hmacKey) = BbsKeyMaterial();
        var document = Fx.Mutate(WindDoc(), vc =>
        {
            ((JsonArray)vc["@context"]!).Add(new JsonObject { ["bn"] = "urn:bnid:" });
            vc["credentialSubject"]!["owner"] = JsonNode.Parse("{" + member + "}");
        });

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(document, BbsOptions(), sk, hmacKey, WindMandatory());

        (await act.Should().ThrowAsync<ProofGenerationException>())
            .WithInnerException<JsonLdDataLossException>().WithMessage("*urn:bnid: namespace*");
    }

    // Skolemization works on compact JSON, so it added an @id to a @json value or an @id map: the reveal
    // document then showed, and the signature covered, a member the issuer never wrote.
    [BbsTheory]
    [InlineData("{\"@id\":\"https://e.example/extra\",\"@type\":\"@json\"}", "{\"a\":1}")]
    [InlineData("{\"@id\":\"https://e.example/extra\",\"@container\":\"@id\"}", "{\"urn:k1\":{\"name\":\"x\"}}")]
    public async Task Bbs2023_CreateBaseProof_SkolemizationThatWouldChangeTheData_ThrowsProofGenerationException(string term, string value)
    {
        var (sk, hmacKey) = BbsKeyMaterial();
        var document = Fx.Mutate(WindDoc(), vc =>
        {
            ((JsonArray)vc["@context"]!).Add(new JsonObject { ["extra"] = JsonNode.Parse(term) });
            vc["credentialSubject"]!["extra"] = JsonNode.Parse(value);
        });

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(document, BbsOptions(), sk, hmacKey, WindMandatory());

        (await act.Should().ThrowAsync<ProofGenerationException>())
            .WithInnerException<JsonLdDataLossException>().WithMessage("*skolemization would change it*");
    }

    // PR #37 review (5685854125): the issuer signs a @json value that already carries an @id, which
    // skolemization leaves alone. Verification skolemized the reveal blindly, so a holder who deleted
    // that member had it re-inserted, recreating the signed bytes: the deletion still verified.
    [BbsFact]
    public async Task Bbs2023_VerifyProof_RevealWhoseSkolemizationWouldRestoreADeletedMember_IsDataLossDetectionError()
    {
        var (sk, hmacKey) = BbsKeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var pipeline = new DataIntegrityProofPipeline(CryptosuiteRegistry.CreateDefault().AddBbs2023());
        var document = Parse("{\"@context\":[\"" + V2 + "\",{\"data\":{\"@id\":\"urn:data\",\"@type\":\"@json\"}}],"
            + "\"@id\":\"urn:doc\",\"type\":\"VerifiableCredential\",\"data\":{\"@id\":\"urn:bnid:_:b0\",\"a\":1}}");
        var baseProof = await suite.CreateBaseProofAsync(document, BbsOptions(), sk, hmacKey, []);
        var secured = Fx.Mutate(document, vc => vc["proof"] = JsonSerializer.SerializeToNode(baseProof, DataProofsJsonOptions.Default));
        var reveal = suite.DeriveProof(secured, ["/data"], Convert.FromHexString("113377aa"));
        var derivedProof = reveal.GetProperty("proof").Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
        var pk = PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, Fx.KeyGen.FromPrivateKey(KeyType.Bls12381G2, sk).PublicKey);

        var deleted = Fx.Mutate(reveal, vc => ((JsonObject)vc["data"]!).Remove("@id"));
        var changed = Fx.Mutate(reveal, vc => vc["data"]!["a"] = 2);
        ProofVerificationResult Direct(JsonElement securedReveal)
            => suite.VerifyProof(Fx.Mutate(securedReveal, vc => vc.Remove("proof")), derivedProof, pk);

        Direct(reveal).Verified.Should().BeTrue();
        pipeline.Verify(reveal, pk).Verified.Should().BeTrue();

        Direct(deleted).Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.DataLossDetectionError);
        var throughPipeline = pipeline.Verify(deleted, pk);
        throughPipeline.Verified.Should().BeFalse();
        throughPipeline.ProofResults.Should().ContainSingle().Which.Problems
            .Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.DataLossDetectionError);

        Direct(changed).Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.ProofVerificationError, "a changed value breaks the signature");
        pipeline.Verify(changed, pk).Verified.Should().BeFalse();
    }

    [BbsFact]
    public async Task Bbs2023_VerifyProof_RevealWithInjectedDroppedNode_IsDataLossDetectionError()
    {
        var (sk, hmacKey) = BbsKeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var baseProof = await suite.CreateBaseProofAsync(WindDoc(), BbsOptions(), sk, hmacKey, WindMandatory());
        var secured = Fx.Mutate(WindDoc(), vc => vc["proof"] = JsonSerializer.SerializeToNode(baseProof, DataProofsJsonOptions.Default));
        var reveal = suite.DeriveProof(secured, ["/credentialSubject/sails/1"], Convert.FromHexString("113377aa"));
        var derivedProof = reveal.GetProperty("proof").Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
        var pk = PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, Fx.KeyGen.FromPrivateKey(KeyType.Bls12381G2, sk).PublicKey);
        var unsecured = Fx.Mutate(reveal, vc => vc.Remove("proof"));

        suite.VerifyProof(unsecured, derivedProof, pk).Verified.Should().BeTrue();

        var tampered = Fx.Mutate(unsecured, vc => vc["credentialSubject"]!["sponsor"] = new JsonObject { ["id"] = "urn:uuid:sponsor[0]", ["name"] = "x" });
        var result = suite.VerifyProof(tampered, derivedProof, pk);

        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.DataLossDetectionError);
    }
}
