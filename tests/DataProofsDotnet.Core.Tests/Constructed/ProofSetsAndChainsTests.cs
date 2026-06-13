using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet;
using DataProofsDotnet.Core.Tests.TestSupport;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Core.Tests.Constructed;

/// <summary>
/// AC-1 step 6: proof sets and proof chains (FR-6), driven by the constructed
/// deterministic <c>eddsa-jcs-2022</c> fixtures under
/// <c>tests/fixtures/constructed/sets-chains/</c> (see that directory's PROVENANCE.md).
/// </summary>
public class ProofSetsAndChainsTests
{
    private static readonly string[] Root = ["constructed", "sets-chains"];
    private static readonly DataIntegrityProofPipeline Pipeline = new();

    private static string[] In(string file) => [.. Root, file];

    private static StaticVerificationMethodResolver Resolver()
    {
        var keys = Fx.Json(In("keys.json"));
        return new StaticVerificationMethodResolver(
        [
            Method(keys, "key-1", "did:example:signer-1"),
            Method(keys, "key-2", "did:example:signer-2"),
        ]);

        static ResolvedVerificationMethod Method(JsonElement keys, string key, string controller)
            => new()
            {
                Id = keys.GetProperty(key).GetProperty("verificationMethodId").GetString()!,
                Controller = controller,
                PublicKey = PublicKeyMaterial.FromMultikey(
                    keys.GetProperty(key).GetProperty("publicKeyMultibase").GetString()!),
                Relationships = new HashSet<string>(StringComparer.Ordinal) { ProofPurposes.AssertionMethod },
            };
    }

    // ------------------------------------------------------------------ (a) proof set

    [Fact]
    public async Task ProofSet_BothProofsVerify()
    {
        var result = await Pipeline.VerifyAsync(
            Fx.Json(In("signed-set-2.json")),
            Resolver(),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeTrue();
        result.ProofResults.Should().HaveCount(2);
        result.ProofResults.Should().OnlyContain(r => r.Verified);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task ProofSet_TamperingWithOneProof_FailsOnlyThatProof(int tamperedIndex)
    {
        var tampered = Fx.Mutate(Fx.Json(In("signed-set-2.json")), node =>
        {
            var proof = (JsonObject)((JsonArray)node["proof"]!)[tamperedIndex]!;
            var proofValue = proof["proofValue"]!.GetValue<string>();
            // Flip the final base58 character (z <-> y keeps it valid base58btc).
            proof["proofValue"] = proofValue[..^1] + (proofValue[^1] == 'z' ? 'y' : 'z');
        });

        var result = await Pipeline.VerifyAsync(
            tampered,
            Resolver(),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeFalse();
        result.ProofResults.Should().HaveCount(2);
        result.ProofResults[tamperedIndex].Verified.Should().BeFalse();
        result.ProofResults[1 - tamperedIndex].Verified.Should().BeTrue();
    }

    // ---------------------------------------------------------------- (b) proof chain

    [Fact]
    public async Task ProofChain_VerifiesWhenDependencyOrderHolds()
    {
        var result = await Pipeline.VerifyAsync(
            Fx.Json(In("signed-chain-2.json")),
            Resolver(),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeTrue();
        result.ProofResults.Should().HaveCount(2);
        result.ProofResults.Should().OnlyContain(r => r.Verified);
    }

    [Fact]
    public async Task ProofChain_TamperingWithPreviousProof_AlsoFailsTheDependentProof()
    {
        // Tampering with proof 1 breaks proof 1 AND proof 2 (whose signing input embeds
        // proof 1's bytes) — the chain property.
        var tampered = Fx.Mutate(Fx.Json(In("signed-chain-2.json")), node =>
        {
            var proof = (JsonObject)((JsonArray)node["proof"]!)[0]!;
            proof["created"] = "2026-01-02T00:00:01Z";
        });

        var result = await Pipeline.VerifyAsync(
            tampered,
            Resolver(),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeFalse();
        result.ProofResults.Should().HaveCount(2);
        result.ProofResults.Should().OnlyContain(r => !r.Verified);
    }

    // ----------------------------------------------- (c) missing / out-of-order chain

    [Fact]
    public async Task ChainWithMissingPreviousProof_FailsWithProofVerificationError()
    {
        var result = await Pipeline.VerifyAsync(
            Fx.Json(In("chain-missing-previous.json")),
            Resolver(),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeFalse();
        result.ProofResults.Should().ContainSingle().Which.Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public async Task ChainOutOfOrder_FailsWithProofVerificationError()
    {
        var result = await Pipeline.VerifyAsync(
            Fx.Json(In("chain-out-of-order.json")),
            Resolver(),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeFalse();
        result.ProofResults.Should().Contain(r => !r.Verified
            && r.Problems.Any(p => p.Code == ProofProblemCodes.ProofVerificationError));
    }

    // ------------------------------------- (d) adding proofs: byte-checked structure

    [Fact]
    public async Task AddingFirstProof_ProducesExpectedBytes()
    {
        var unsigned = Fx.Json(In("unsigned.json"));
        var options = ReadOptions("set-proof-1-options.json");

        var secured = await Pipeline.AddProofAsync(unsigned, options, Fx.Signer(Fx.SeedKey(0x11)));

        Fx.Compact(secured).Should().Be(Fx.Text(In("signed-set-1.json")));
        secured.GetProperty("proof").ValueKind.Should().Be(JsonValueKind.Object);
    }

    [Fact]
    public async Task AddingSecondProof_ToProofedDocument_ProducesExpectedSetBytes()
    {
        var signedOnce = Fx.Json(In("signed-set-1.json"));
        var options = ReadOptions("set-proof-2-options.json");

        var secured = await Pipeline.AddProofAsync(signedOnce, options, Fx.Signer(Fx.SeedKey(0x12)));

        // Spec-correct set structure: existing object proof -> two-element array,
        // original proof untouched, new proof appended — byte-checked.
        Fx.Compact(secured).Should().Be(Fx.Text(In("signed-set-2.json")));
        secured.GetProperty("proof").ValueKind.Should().Be(JsonValueKind.Array);
        secured.GetProperty("proof").GetArrayLength().Should().Be(2);
    }

    [Fact]
    public async Task AddingChainedProof_ProducesExpectedChainBytes()
    {
        var signedOnce = Fx.Json(In("signed-chain-1.json"));
        var options = ReadOptions("chain-proof-2-options.json");

        var secured = await Pipeline.AddProofAsync(signedOnce, options, Fx.Signer(Fx.SeedKey(0x12)));

        Fx.Compact(secured).Should().Be(Fx.Text(In("signed-chain-2.json")));
        var proofs = secured.GetProperty("proof");
        proofs.GetArrayLength().Should().Be(2);
        proofs[1].GetProperty("previousProof").GetString()
            .Should().Be(proofs[0].GetProperty("id").GetString());
    }

    [Fact]
    public async Task AddingChainedProof_WithDanglingPreviousProof_ThrowsProofGenerationException()
    {
        var unsigned = Fx.Json(In("unsigned.json"));
        var options = ReadOptions("chain-proof-2-options.json"); // references a proof id that is absent

        var act = () => Pipeline.AddProofAsync(unsigned, options, Fx.Signer(Fx.SeedKey(0x12)));

        await act.Should().ThrowAsync<ProofGenerationException>();
    }

    private static DataIntegrityProof ReadOptions(string file)
        => Fx.Json(In(file)).Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
}
