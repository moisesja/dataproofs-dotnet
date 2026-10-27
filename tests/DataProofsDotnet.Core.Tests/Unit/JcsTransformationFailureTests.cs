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
/// </summary>
public sealed class JcsTransformationFailureTests
{
    private const string Context = "https://www.w3.org/ns/credentials/v2";

    public static TheoryData<string> HostileDocuments => new()
    {
        // A JSON escape for an unpaired surrogate: valid UTF-8 on the wire, untranscodable as a string.
        "{\"@context\":[\"" + Context + "\"],\"x\":\"\\uD800\"}",
        // Nested past System.Text.Json's default maximum depth of 64.
        "{\"@context\":[\"" + Context + "\"],\"x\":" + string.Concat(Enumerable.Repeat("{\"a\":", 100)) + "1" + new string('}', 100) + "}",
    };

    [Theory]
    [MemberData(nameof(HostileDocuments))]
    public async Task VerifyProof_UntransformableDocument_WithProofContext_IsTransformationError(string hostile)
    {
        var suite = new EddsaJcs2022Cryptosuite();
        var key = Fx.SeedKey(0x01);
        var proof = await suite.CreateProofAsync(
            Parse("{\"@context\":[\"" + Context + "\"],\"k\":\"v\"}"),
            new DataIntegrityProof
            {
                Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
                Created = "2026-01-01T00:00:00Z",
                VerificationMethod = "did:example:alice#key-1",
                ProofPurpose = ProofPurposes.AssertionMethod,
            },
            Fx.Signer(key));
        proof.Context.Should().NotBeNull("the rewrite path under test runs only for a proof carrying @context");

        var result = suite.VerifyProof(Parse(hostile), proof, PublicKeyMaterial.FromRaw(key.KeyType, key.PublicKey));

        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.ProofTransformationError);
    }

    private static JsonElement Parse(string json)
    {
        using var document = JsonDocument.Parse(Encoding.UTF8.GetBytes(json), new JsonDocumentOptions { MaxDepth = 256 });
        return document.RootElement.Clone();
    }
}
