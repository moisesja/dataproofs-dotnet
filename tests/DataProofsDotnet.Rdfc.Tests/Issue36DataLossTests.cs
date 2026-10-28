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

    private static readonly RdfcDocumentCanonicalizer Canonicalizer = new();

    /// <summary>A credential over <paramref name="contexts"/> whose own terms are all defined, plus <paramref name="members"/>.</summary>
    private static string Vc(string members, string contexts = "\"" + V2 + "\"")
        => "{\"@context\":[" + contexts + "],\"id\":\"urn:uuid:36363636-0000-4000-8000-000000000036\","
            + "\"type\":\"VerifiableCredential\",\"issuer\":\"did:example:issuer\"," + members + "}";

    private static string Subject(string members) => "\"credentialSubject\":{\"id\":\"did:example:alice\"," + members + "}";

    /// <summary>The credentials/v2 context followed by an inline context object.</summary>
    private static string V2With(string inlineContext) => "\"" + V2 + "\"," + inlineContext;

    private static readonly string WithUndefinedTerms = "\"" + V2 + "\",\"" + UndefinedTerms + "\"";

    // Built at run time from its code point, so no tool can decode an escape into the source.
    private static readonly string Grinning = char.ConvertFromUtf32(0x1F600);

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
