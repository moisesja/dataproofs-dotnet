using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Legacy.Tests.TestSupport;
using FluentAssertions;
using NetCid;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Legacy.Tests;

/// <summary>
/// Tamper detection for both legacy suites: flipping a document byte or a <c>proofValue</c> byte
/// must yield <c>verified == false</c> — never an exception (FR-3, fail-closed).
/// </summary>
public class TamperDetectionTests
{
    public static TheoryData<string, KeyType> Suites() => new()
    {
        { Ed25519Signature2020Cryptosuite.ProofType, KeyType.Ed25519 },
        { EcdsaSecp256r1Signature2019Cryptosuite.ProofType, KeyType.P256 },
    };

    private static ICryptosuite Suite(string legacyType)
        => legacyType == Ed25519Signature2020Cryptosuite.ProofType
            ? new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Jcs)
            : new EcdsaSecp256r1Signature2019Cryptosuite(LegacyCanonicalization.Jcs);

    private static async Task<(DataIntegrityProofPipeline Pipeline, JsonElement Secured, PublicKeyMaterial PublicKey)>
        SignedAsync(string legacyType, KeyType keyType)
    {
        var registry = CryptosuiteRegistry.CreateDefault();
        registry.Register(Suite(legacyType));
        var pipeline = new DataIntegrityProofPipeline(registry);

        var keyPair = Fx.SeedKey(0x0B, keyType);
        var signer = Fx.Signer(keyPair);
        var publicKey = PublicKeyMaterial.FromRaw(keyType, keyPair.PublicKey);
        var methodId = $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}";

        var document = JsonSerializer.Deserialize<JsonElement>("""
            { "@context": "https://www.w3.org/ns/credentials/v2", "id": "urn:uuid:tamper", "claim": "original" }
            """);

        var proofOptions = new DataIntegrityProof
        {
            Type = legacyType,
            Cryptosuite = legacyType,
            VerificationMethod = methodId,
            ProofPurpose = ProofPurposes.AssertionMethod,
            Created = "2026-06-14T00:00:00.000000Z",
        };

        var secured = await pipeline.AddProofAsync(document, proofOptions, signer);
        return (pipeline, secured, publicKey);
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task TamperedDocument_FailsClosed(string legacyType, KeyType keyType)
    {
        var (pipeline, secured, publicKey) = await SignedAsync(legacyType, keyType);

        var tampered = Fx.Mutate(secured, node => node["claim"] = "tampered");

        var act = () => pipeline.Verify(tampered, publicKey);
        var result = act.Should().NotThrow().Subject;
        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task FlippedProofValueByte_FailsClosed(string legacyType, KeyType keyType)
    {
        var (pipeline, secured, publicKey) = await SignedAsync(legacyType, keyType);

        // Decode the multibase signature, flip one byte, re-encode — a structurally valid
        // base58-btc proofValue that simply does not verify.
        var original = secured.GetProperty("proof").GetProperty("proofValue").GetString()!;
        Multibase.TryDecode(original, out var sig, out _).Should().BeTrue();
        sig[0] ^= 0xFF;
        var flipped = Multibase.Encode(sig, MultibaseEncoding.Base58Btc);

        var tampered = Fx.Mutate(secured, node => ((JsonObject)node["proof"]!)["proofValue"] = flipped);

        var act = () => pipeline.Verify(tampered, publicKey);
        var result = act.Should().NotThrow().Subject;
        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task WrongKey_FailsClosed(string legacyType, KeyType keyType)
    {
        var (pipeline, secured, _) = await SignedAsync(legacyType, keyType);

        var wrongKey = PublicKeyMaterial.FromRaw(keyType, Fx.SeedKey(0x0C, keyType).PublicKey);

        var act = () => pipeline.Verify(secured, wrongKey);
        var result = act.Should().NotThrow().Subject;
        result.Verified.Should().BeFalse();
    }
}
