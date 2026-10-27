using System.Text;
using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.Core.Tests.TestSupport;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Core.Tests.Unit;

/// <summary>
/// Issue #27: JCS verification of a proof carrying <c>@context</c> rewrites the document's
/// <c>@context</c> and now canonicalizes the result as a <see cref="JsonElement"/> (NetCid's
/// <c>JsonNode</c> overloads use reflection internally). A document that cannot be transformed must
/// still fail as <see cref="ProofProblemCodes.ProofTransformationError"/>, as it did when NetCid's node
/// path reported it as a <c>JcsFormatException</c>, not as the generic verification error.
/// Only that conversion is mapped: the same untranscodable value in a proof member keeps the generic
/// verification error it had before #27, so broadening the mapping is a visible decision, not a side
/// effect (PR #32 review).
/// </summary>
public sealed class JcsTransformationFailureTests
{
    private const string Context = "https://www.w3.org/ns/credentials/v2";

    // A JSON escape for an unpaired surrogate: valid UTF-8 on the wire, untranscodable as a string.
    private const string Untranscodable = "\"\\uD800\"";

    public static TheoryData<string> HostileDocuments => new()
    {
        // The untranscodable value in the document that the @context rewrite converts.
        "{\"@context\":[\"" + Context + "\"],\"x\":" + Untranscodable + "}",
        // Nested past System.Text.Json's default maximum depth of 64.
        "{\"@context\":[\"" + Context + "\"],\"x\":" + string.Concat(Enumerable.Repeat("{\"a\":", 100)) + "1" + new string('}', 100) + "}",
    };

    [Theory]
    [MemberData(nameof(HostileDocuments))]
    public async Task VerifyProof_UntransformableDocument_WithProofContext_IsTransformationError(string hostile)
    {
        var (suite, proof, publicKey) = await SignedProofAsync();
        proof.Context.Should().NotBeNull("the rewrite path under test runs only for a proof carrying @context");

        var result = suite.VerifyProof(Parse(hostile), proof, publicKey);

        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.ProofTransformationError);
    }

    [Fact]
    public async Task VerifyProof_UntranscodableProofExtension_KeepsTheGenericVerificationError()
    {
        // The same value, in a proof member instead of the document: serializing the proof
        // configuration throws, outside the one mapped conversion. "Verification failed unexpectedly"
        // proves the exception path was taken; a value that serialized cleanly would also fail, but as
        // a signature mismatch, and could not tell a broadened mapping apart.
        var (suite, proof, publicKey) = await SignedProofAsync();
        var hostileProof = proof with
        {
            AdditionalProperties = new Dictionary<string, JsonElement> { ["x"] = Parse(Untranscodable) },
        };

        var result = suite.VerifyProof(Parse(SignedDocument), hostileProof, publicKey);

        result.Verified.Should().BeFalse();
        var problem = result.Problems.Should().ContainSingle().Subject;
        problem.Code.Should().Be(ProofProblemCodes.ProofVerificationError);
        problem.Message.Should().StartWith("Verification failed unexpectedly");
    }

    [Fact]
    public async Task Verify_UntranscodableProofExtension_ThroughThePipeline_KeepsTheGenericVerificationError()
    {
        // End to end through the public pipeline: a secured document whose proof carries the
        // untranscodable value (the review's reproduction).
        var key = Fx.SeedKey(0x01);
        var pipeline = new DataIntegrityProofPipeline();
        var secured = await pipeline.AddProofAsync(Parse(SignedDocument), Options(), Fx.Signer(key));
        var hostile = Parse(secured.GetRawText().Replace("\"proofValue\"", "\"x\":" + Untranscodable + ",\"proofValue\"", StringComparison.Ordinal));

        var result = pipeline.Verify(hostile, PublicKeyMaterial.FromRaw(key.KeyType, key.PublicKey));

        result.Verified.Should().BeFalse();
        var problem = result.ProofResults.Should().ContainSingle().Subject.Problems.Should().ContainSingle().Subject;
        problem.Code.Should().Be(ProofProblemCodes.ProofVerificationError);
        problem.Message.Should().StartWith("Verification failed unexpectedly");
    }

    private const string SignedDocument = "{\"@context\":[\"" + Context + "\"],\"k\":\"v\"}";

    private static DataIntegrityProof Options() => new()
    {
        Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
        Created = "2026-01-01T00:00:00Z",
        VerificationMethod = "did:example:alice#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    private static async Task<(EddsaJcs2022Cryptosuite Suite, DataIntegrityProof Proof, PublicKeyMaterial PublicKey)> SignedProofAsync()
    {
        var suite = new EddsaJcs2022Cryptosuite();
        var key = Fx.SeedKey(0x01);
        var proof = await suite.CreateProofAsync(Parse(SignedDocument), Options(), Fx.Signer(key));
        return (suite, proof, PublicKeyMaterial.FromRaw(key.KeyType, key.PublicKey));
    }

    private static JsonElement Parse(string json)
    {
        using var document = JsonDocument.Parse(Encoding.UTF8.GetBytes(json), new JsonDocumentOptions { MaxDepth = 256 });
        return document.RootElement.Clone();
    }
}
