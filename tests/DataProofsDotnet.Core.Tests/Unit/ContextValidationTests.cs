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
    public async Task KnownContexts_UnknownValue_FailsTheDocumentAfterTheProofVerified()
    {
        var secured = await SignAsync("[\"" + V2 + "\",\"" + Unknown + "\"]");

        var result = Verify(secured, Known);

        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle().Which.Should().BeEquivalentTo(new
        {
            Code = ProofProblemCodes.ProofVerificationError,
            Message = "The secured document's @context holds a value that is not a known context.",
        });
        result.ProofResults.Should().ContainSingle().Which.Verified.Should().BeTrue("the proof itself verified; the context is what fails");
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
    public async Task KnownContexts_FailedProofAndUnknownContext_ReportsBoth()
    {
        var secured = await SignAsync("[\"" + V2 + "\",\"" + Unknown + "\"]");
        var wrongKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, Fx.SeedKey(0x08).PublicKey);

        var result = Pipeline.Verify(secured, wrongKey, new ProofVerificationOptions { KnownContexts = Known });

        result.Verified.Should().BeFalse();
        result.ProofResults.Should().ContainSingle().Which.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle().Which.Message.Should().Contain("not a known context");
    }
}
