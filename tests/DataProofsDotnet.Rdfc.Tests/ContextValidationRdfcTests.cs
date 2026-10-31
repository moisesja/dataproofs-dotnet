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
/// VC Data Integrity 1.0 §4.6 Context Validation over RDFC proofs (PR #42 review). A proof over RDF
/// binds statements, not the JSON that compacted them, so a holder can relabel a term after signing
/// and the proof still verifies. JCS cannot show this, because any change breaks a JCS proof.
/// </summary>
public sealed class ContextValidationRdfcTests
{
    private const string V2 = "https://www.w3.org/ns/credentials/v2";
    private const string Nickname = "{\"nickname\":\"https://schema.org/name\"}";

    private static readonly DataIntegrityProofPipeline Pipeline = new(RdfcCryptosuiteRegistration.CreateWithRdfcSuites());
    private static readonly KeyPair Key = Fx.KeyGen.FromPrivateKey(KeyType.Ed25519, Enumerable.Repeat((byte)0x46, 32).ToArray());
    private static readonly PublicKeyMaterial PublicKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, Key.PublicKey);

    private static Task<JsonElement> SignAsync(string members)
        => Pipeline.AddProofAsync(
            JsonDocument.Parse("{\"@context\":\"" + V2 + "\",\"id\":\"urn:uuid:46464646-0000-4000-8000-000000000046\","
                + "\"type\":\"VerifiableCredential\",\"issuer\":\"did:example:issuer\"," + members + "}").RootElement.Clone(),
            new DataIntegrityProof
            {
                Cryptosuite = EddsaRdfc2022Cryptosuite.CryptosuiteName,
                Created = "2026-10-30T00:00:00Z",
                VerificationMethod = "did:example:issuer#key-1",
                ProofPurpose = ProofPurposes.AssertionMethod,
            },
            Fx.Signer(Key));

    private static Task<JsonElement> SignedCredentialAsync() => SignAsync("\"credentialSubject\":{\"id\":\"did:example:alice\",\"name\":\"Alice\"}");

    private static DocumentVerificationResult Verify(JsonElement secured, IReadOnlyCollection<string>? knownContexts)
        => Pipeline.Verify(secured, PublicKey, new ProofVerificationOptions { KnownContexts = knownContexts });

    /// <summary>Renames the subject's <c>name</c> to <c>nickname</c> under a context added after signing.</summary>
    private static JsonElement Relabel(JsonElement secured, string contextJson, bool asArray = false)
        => Fx.Mutate(secured, document =>
        {
            JsonObject subject = new()
            {
                ["id"] = "did:example:alice",
                ["@context"] = JsonNode.Parse(contextJson),
                ["nickname"] = "Alice",
            };
            document["credentialSubject"] = asArray ? new JsonArray(subject) : subject;
        });

    public static TheoryData<string, string, bool> Relabelings() => new()
    {
        // case, the context the holder adds, whether the subject moves into an array
        { "inline object on the subject", Nickname, false },
        { "inline object on a subject inside an array", Nickname, true },
        { "listed IRI and inline object", "[\"" + V2 + "\"," + Nickname + "]", false },
    };

    [Theory]
    [MemberData(nameof(Relabelings))]
    public async Task KnownContexts_NestedContextAddedAfterSigning_FailsThoughTheProofStillVerifies(string @case, string contextJson, bool asArray)
    {
        var relabeled = Relabel(await SignedCredentialAsync(), contextJson, asArray);

        Verify(relabeled, null).Verified.Should().BeTrue("{0}: the RDF is unchanged, so the signature cannot catch this", @case);

        var result = Verify(relabeled, [V2]);

        result.Verified.Should().BeFalse(@case);
        result.ProofResults.Should().ContainSingle().Which.Verified.Should().BeTrue();
        result.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public async Task KnownContexts_UntouchedCredential_Verifies()
    {
        Verify(await SignedCredentialAsync(), [V2]).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task KnownContexts_ContextUnderAMapKeyNamedValue_Fails()
    {
        // @value is a keyword only outside a container map. Under an @id container it is an ordinary key
        // whose value the processor expands, applying the @context inside it, so nothing can be skipped
        // by name. The listed context is one a verifier could reasonably hold.
        const string Listed = "https://ctx.example/v1";
        var loader = new MapLoader(new Dictionary<string, string>
        {
            [Listed] = "{\"@context\":{\"@version\":1.1,\"things\":{\"@id\":\"https://ctx.example/things\",\"@container\":\"@id\"},\"boards\":\"https://ctx.example/boards\"}}",
        });
        var pipeline = new DataIntegrityProofPipeline(RdfcCryptosuiteRegistration.CreateWithRdfcSuites(new RdfcDocumentCanonicalizer(loader)));
        var signed = await pipeline.AddProofAsync(
            JsonDocument.Parse("{\"@context\":[\"" + V2 + "\",\"" + Listed + "\"],\"id\":\"urn:uuid:46464646-0000-4000-8000-000000000046\","
                + "\"type\":\"VerifiableCredential\",\"issuer\":\"did:example:issuer\","
                + "\"credentialSubject\":{\"id\":\"did:example:alice\",\"name\":\"Alice\"},"
                + "\"things\":{\"did:example:board\":{\"boards\":\"4\"}}}").RootElement.Clone(),
            new DataIntegrityProof
            {
                Cryptosuite = EddsaRdfc2022Cryptosuite.CryptosuiteName,
                Created = "2026-10-30T00:00:00Z",
                VerificationMethod = "did:example:issuer#key-1",
                ProofPurpose = ProofPurposes.AssertionMethod,
            },
            Fx.Signer(Key));

        // boards is now presented as sails, read through a context nobody listed.
        var relabeled = Fx.Mutate(signed, document => document["things"] = JsonNode.Parse(
            "{\"@value\":{\"id\":\"did:example:board\",\"@context\":{\"sails\":\"https://ctx.example/boards\"},\"sails\":\"4\"}}"));

        pipeline.Verify(relabeled, PublicKey).Verified.Should().BeTrue("the RDF is unchanged, so the signature cannot catch this");

        var result = pipeline.Verify(relabeled, PublicKey, new ProofVerificationOptions { KnownContexts = [V2, Listed] });

        result.Verified.Should().BeFalse();
        result.ProofResults.Should().ContainSingle().Which.Verified.Should().BeTrue();
        result.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public async Task KnownContexts_JsonLiteralHoldingAContextKey_FailsThoughItsProofVerifies()
    {
        // Telling a literal from a live context takes processing the contexts, so the key counts anyway.
        // A false refusal, never a false accept.
        var secured = await SignAsync("\"credentialSubject\":{\"id\":\"did:example:alice\",\"https://e.example/data\":"
            + "{\"@type\":\"@json\",\"@value\":{\"@context\":" + Nickname + ",\"nickname\":\"Alice\"}}}");

        var result = Verify(secured, [V2]);

        result.Verified.Should().BeFalse();
        result.ProofResults.Should().ContainSingle().Which.Verified.Should().BeTrue();
    }

    private sealed class MapLoader(Dictionary<string, string> contexts) : IDocumentLoader
    {
        public LoadedContextDocument Load(Uri url) => contexts.TryGetValue(url.AbsoluteUri, out var content)
            ? new LoadedContextDocument(url, content)
            : OfflineDocumentLoader.Instance.Load(url);
    }
}
