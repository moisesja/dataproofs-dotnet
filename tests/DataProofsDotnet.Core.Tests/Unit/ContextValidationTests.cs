using System.Text.Json;
using DataProofsDotnet.Core.Tests.TestSupport;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Core.Tests.Unit;

/// <summary>
/// VC Data Integrity 1.0 §4.6 Context Validation through <see cref="ProofVerificationOptions.KnownContexts"/>
/// (PR #42). A proof over RDF binds statements, not the JSON that compacted them, so a holder can
/// present a verified document under a <c>@context</c> that reads its terms differently; the
/// specification requires applications to accept only known contexts, after verifying the proofs.
/// </summary>
public class ContextValidationTests
{
    private const string V2 = "https://www.w3.org/ns/credentials/v2";
    private const string Examples = "https://www.w3.org/ns/credentials/examples/v2";
    private const string Unknown = "https://evil.example/contexts/v1";

    private static readonly DataIntegrityProofPipeline Pipeline = new();
    private static readonly KeyPair Key = Fx.SeedKey(0x07);
    private static readonly PublicKeyMaterial PublicKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, Key.PublicKey);
    private static readonly string[] Known = [V2, Examples];

    private static JsonElement Doc(string json) => JsonDocument.Parse(json).RootElement.Clone();

    private static Task<JsonElement> SignAsync(string contextJson)
        => Pipeline.AddProofAsync(
            Doc("{\"@context\":" + contextJson + ",\"id\":\"urn:uuid:ctx\",\"type\":\"VerifiableCredential\",\"issuer\":\"did:example:alice\"}"),
            new DataIntegrityProof
            {
                Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
                Created = "2026-01-01T00:00:00Z",
                VerificationMethod = "did:example:alice#key-1",
                ProofPurpose = ProofPurposes.AssertionMethod,
            },
            new KeyPairSigner(Key, new DefaultCryptoProvider()));

    private static DocumentVerificationResult Verify(JsonElement secured, IReadOnlyCollection<string>? knownContexts)
        => Pipeline.Verify(secured, PublicKey, new ProofVerificationOptions { KnownContexts = knownContexts });

    [Fact]
    public async Task KnownContexts_Unset_IsNotChecked()
    {
        var secured = await SignAsync("[\"" + V2 + "\",\"" + Unknown + "\"]");

        Pipeline.Verify(secured, PublicKey).Verified.Should().BeTrue();
        Verify(secured, null).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task KnownContexts_EveryValueKnown_Verifies()
    {
        var array = await SignAsync("[\"" + V2 + "\",\"" + Examples + "\"]");
        var single = await SignAsync("\"" + V2 + "\"");

        Verify(array, Known).Verified.Should().BeTrue();
        Verify(single, Known).Verified.Should().BeTrue();
        Verify(single, [V2]).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task KnownContexts_UnknownValue_FailsTheDocumentBeforeAnyProofIsVerified()
    {
        var secured = await SignAsync("[\"" + V2 + "\",\"" + Unknown + "\"]");

        var result = Verify(secured, Known);

        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle().Which.Should().BeEquivalentTo(new
        {
            Code = ProofProblemCodes.ProofVerificationError,
            Message = "A @context in the secured document holds a value that is not a known context.",
        });
        result.ProofResults.Should().BeEmpty("an unlisted context is refused before anything could load it");
        result.Problems.Single().Message.Should().NotContain(Unknown, "messages do not quote the input");
    }

    [Fact]
    public async Task KnownContexts_SingleUnknownString_Fails()
    {
        var secured = await SignAsync("\"" + Unknown + "\"");

        Verify(secured, Known).Verified.Should().BeFalse();
    }

    [Fact]
    public async Task KnownContexts_InlineContextObject_Fails()
    {
        // An object cannot be a listed value; it could redefine any term.
        var secured = await SignAsync("[\"" + V2 + "\",{\"issuer\":\"https://evil.example/vocab#issuer\"}]");

        var result = Verify(secured, Known);

        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle().Which.Message.Should().Contain("not a context IRI");
    }

    [Fact]
    public async Task KnownContexts_DocumentWithoutContext_Passes()
    {
        var secured = await Pipeline.AddProofAsync(
            Doc("{\"id\":\"urn:uuid:plain\",\"claim\":\"value\"}"),
            new DataIntegrityProof
            {
                Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
                Created = "2026-01-01T00:00:00Z",
                VerificationMethod = "did:example:alice#key-1",
                ProofPurpose = ProofPurposes.AssertionMethod,
            },
            new KeyPairSigner(Key, new DefaultCryptoProvider()));

        Verify(secured, Known).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task KnownContexts_AppliesOnTheResolverPath()
    {
        var secured = await SignAsync("[\"" + V2 + "\",\"" + Unknown + "\"]");
        var resolver = Fx.SingleMethodResolver("did:example:alice#key-1", Key.MultibasePublicKey);

        var known = await Pipeline.VerifyAsync(secured, resolver, new ProofVerificationOptions { KnownContexts = [V2, Unknown] });
        var unknown = await Pipeline.VerifyAsync(secured, resolver, new ProofVerificationOptions { KnownContexts = Known });

        known.Verified.Should().BeTrue();
        unknown.Verified.Should().BeFalse();
        unknown.Problems.Should().ContainSingle();
    }

    [Fact]
    public async Task KnownContexts_UnknownContext_IsReportedWithoutVerifyingTheProof()
    {
        var secured = await SignAsync("[\"" + V2 + "\",\"" + Unknown + "\"]");
        var wrongKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, Fx.SeedKey(0x08).PublicKey);

        var result = Pipeline.Verify(secured, wrongKey, new ProofVerificationOptions { KnownContexts = Known });

        result.Verified.Should().BeFalse();
        result.ProofResults.Should().BeEmpty();
        result.Problems.Should().ContainSingle().Which.Message.Should().Contain("not a known context");
    }

    // ------------------------------------------------------------------ nested contexts

    private const string NotAKnownContext = "not a known context";
    private const string NotAContextIri = "not a context IRI";
    private const string InlineContext = "{\"nickname\":\"https://evil.example/vocab#nickname\"}";

    /// <summary>A credential under the V2 context, plus <paramref name="members"/>.</summary>
    private static string Vc(string members)
        => "{\"@context\":\"" + V2 + "\",\"id\":\"urn:uuid:ctx\",\"type\":\"VerifiableCredential\",\"issuer\":\"did:example:issuer\"," + members + "}";

    private static Task<JsonElement> SignDocumentAsync(string json)
        => Pipeline.AddProofAsync(
            Doc(json),
            new DataIntegrityProof
            {
                Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
                Created = "2026-01-01T00:00:00Z",
                VerificationMethod = "did:example:alice#key-1",
                ProofPurpose = ProofPurposes.AssertionMethod,
            },
            new KeyPairSigner(Key, new DefaultCryptoProvider()));

    public static TheoryData<string, string, string> UnacceptedNestedContexts()
    {
        var unlisted = "\"@context\":\"" + Unknown + "\"";
        var inline = "\"@context\":" + InlineContext;
        return new()
        {
            // case, document, the message's phrase. Every container JSON-LD descends into, and the shapes a
            // root-only reading would miss.
            { "inline object in a node", Vc("\"credentialSubject\":{\"id\":\"did:example:alice\"," + inline + ",\"nickname\":\"Alice\"}"), NotAContextIri },
            { "unlisted IRI in a node", Vc("\"credentialSubject\":{" + unlisted + ",\"name\":\"Alice\"}"), NotAKnownContext },
            { "listed and inline together", Vc("\"credentialSubject\":{\"@context\":[\"" + V2 + "\"," + InlineContext + "]}"), NotAContextIri },
            { "listed and unlisted together", Vc("\"credentialSubject\":{\"@context\":[\"" + V2 + "\",\"" + Unknown + "\"]}"), NotAKnownContext },
            { "null, which clears the active context", Vc("\"credentialSubject\":{\"@context\":null}"), NotAContextIri },
            { "in an array of nodes", Vc("\"credentialSubject\":[{\"id\":\"did:example:a\"},{" + inline + "}]"), NotAContextIri },
            { "in an array inside an array", Vc("\"claims\":[[{" + inline + "}]]"), NotAContextIri },
            { "several levels down", Vc("\"a\":{\"b\":{\"c\":[{\"d\":{" + inline + "}}]}}"), NotAContextIri },
            { "under @graph", Vc("\"@graph\":[{" + inline + "}]"), NotAContextIri },
            { "under @included", Vc("\"@included\":[{" + inline + "}]"), NotAContextIri },
            { "under @reverse", Vc("\"@reverse\":{\"https://e.example/p\":{" + inline + "}}"), NotAContextIri },
            { "under @nest", Vc("\"@nest\":{" + inline + "}"), NotAContextIri },
            { "in a map", Vc("\"labels\":{\"en\":{" + inline + "}}"), NotAContextIri },
            { "beside a @value", Vc("\"name\":{" + inline + ",\"@value\":\"Alice\"}"), NotAContextIri },
            { "in a presentation's embedded credential", Vc("\"verifiableCredential\":[{\"@context\":[\"" + V2 + "\",\"" + Unknown + "\"],\"type\":\"VerifiableCredential\"}]"), NotAKnownContext },
            { "with the key escaped", Vc("\"credentialSubject\":{\"\\u0040context\":" + InlineContext + "}"), NotAContextIri },
            { "with no @context at the root", "{\"id\":\"urn:uuid:ctx\",\"credentialSubject\":{" + inline + "}}", NotAContextIri },
        };
    }

    [Theory]
    [MemberData(nameof(UnacceptedNestedContexts))]
    public async Task KnownContexts_UnacceptedNestedContext_FailsTheDocument(string @case, string document, string phrase)
    {
        var secured = await SignDocumentAsync(document);

        Pipeline.Verify(secured, PublicKey).Verified.Should().BeTrue("{0}: the proof is sound; the context is what fails", @case);

        var result = Verify(secured, [V2]);

        result.Verified.Should().BeFalse(@case);
        var problem = result.Problems.Should().ContainSingle().Which;
        problem.Code.Should().Be(ProofProblemCodes.ProofVerificationError);
        problem.Message.Should().Contain(phrase).And.NotContain("evil.example", "messages do not quote the input");
    }

    public static TheoryData<string, string> AcceptedNestedContexts() => new()
    {
        // case, document. A listed context nested gives a holder nothing that listing it at the root
        // does not, and §4.6's literal "any subtree" would refuse every presentation.
        { "listed IRI in a node", Vc("\"credentialSubject\":{\"@context\":\"" + V2 + "\",\"name\":\"Alice\"}") },
        { "listed array in a node", Vc("\"credentialSubject\":{\"@context\":[\"" + V2 + "\",\"" + Examples + "\"]}") },
        { "a presentation's embedded credentials", Vc("\"verifiableCredential\":[{\"@context\":[\"" + V2 + "\",\"" + Examples + "\"],\"type\":\"VerifiableCredential\"}]") },
    };

    [Theory]
    [MemberData(nameof(AcceptedNestedContexts))]
    public async Task KnownContexts_AcceptedNestedContext_Verifies(string @case, string document)
    {
        var secured = await SignDocumentAsync(document);

        Verify(secured, Known).Verified.Should().BeTrue(@case);
    }

    public static TheoryData<string, string> JsonLiteralsHoldingAContextKey() => new()
    {
        // case, document. Telling these from a live context takes processing the contexts, and Core has no
        // JSON-LD processor: a term's type can make a literal, and @value is a keyword only outside a
        // container map. So the key counts: a false refusal, never a false accept.
        { "typed by a term, as credentials/v2 types jsonSchema", Vc("\"credentialSubject\":{\"type\":\"JsonSchema\",\"jsonSchema\":{\"properties\":{\"@context\":{\"type\":\"array\"}}}}") },
        { "an explicit @json value object", Vc("\"data\":{\"@type\":\"@json\",\"@value\":{\"@context\":" + InlineContext + "}}") },
    };

    [Theory]
    [MemberData(nameof(JsonLiteralsHoldingAContextKey))]
    public async Task KnownContexts_JsonLiteralHoldingAContextKey_FailsClosed(string @case, string document)
    {
        var secured = await SignDocumentAsync(document);

        var result = Verify(secured, Known);

        result.Verified.Should().BeFalse(@case);
        result.Problems.Should().ContainSingle().Which.Message.Should().Contain(NotAContextIri);
    }

    [Fact]
    public void KnownContexts_W3cVectorCarryingAContextInItsProof_Verifies()
    {
        // The JCS suites copy @context into the proof, so a literal reading of §4.6 step 3 ("any subtree")
        // would refuse every JCS proof, this W3C vector included.
        var signed = Fx.Json("w3c", "vc-di-eddsa", "TestVectors", "eddsa-jcs-2022", "signedJCS.json");
        var keys = Fx.Json("w3c", "vc-di-eddsa", "TestVectors", "keyPair.json");
        signed.GetProperty("proof").TryGetProperty("@context", out _).Should().BeTrue();

        var result = Pipeline.Verify(
            signed,
            PublicKeyMaterial.FromMultikey(keys.GetProperty("publicKeyMultibase").GetString()!),
            new ProofVerificationOptions { KnownContexts = Known });

        result.Verified.Should().BeTrue();
    }
}
