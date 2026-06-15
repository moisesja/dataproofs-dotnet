using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Legacy.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Legacy.Tests;

/// <summary>
/// Extension-field (e.g. <c>capabilityChain</c>) byte-identity: any unmodeled proof member must
/// ride through <see cref="DataIntegrityProof.AdditionalProperties"/> into the signing input,
/// so a proof carrying it verifies — and TAMPERING the extension must fail the signature closed.
/// This is the exact cross-stack break zcap warns against (a hand-picked proof-field whitelist).
/// </summary>
public class ExtensionFieldRoundTripTests
{
    private static (DataIntegrityProofPipeline Pipeline, KeyPairSigner Signer, PublicKeyMaterial PublicKey, string MethodId)
        Setup()
    {
        var registry = CryptosuiteRegistry.CreateDefault();
        registry.Register(new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Jcs));
        var pipeline = new DataIntegrityProofPipeline(registry);

        var keyPair = Fx.SeedKey(0x09, KeyType.Ed25519);
        var signer = Fx.Signer(keyPair);
        var publicKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, keyPair.PublicKey);
        var methodId = $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}";
        return (pipeline, signer, publicKey, methodId);
    }

    private static JsonElement Document() => JsonSerializer.Deserialize<JsonElement>("""
        {
          "@context": "https://w3id.org/zcap/v1",
          "id": "urn:uuid:ext-roundtrip",
          "parentCapability": "urn:zcap:root:resource",
          "invocationTarget": "https://example.com/resource"
        }
        """);

    private static DataIntegrityProof ProofOptionsWithExtension(string methodId)
        => new DataIntegrityProof
        {
            Type = Ed25519Signature2020Cryptosuite.ProofType,
            Cryptosuite = Ed25519Signature2020Cryptosuite.ProofType,
            VerificationMethod = methodId,
            ProofPurpose = ProofPurposes.CapabilityDelegation,
            Created = "2026-06-14T00:00:00.000000Z",
            AdditionalProperties = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
            {
                ["capabilityChain"] = JsonSerializer.Deserialize<JsonElement>("""["urn:zcap:root:resource"]"""),
            },
        };

    [Fact]
    public async Task ProofWithCapabilityChain_RoundTrips_AndVerifies()
    {
        var (pipeline, signer, publicKey, methodId) = Setup();

        var secured = await pipeline.AddProofAsync(Document(), ProofOptionsWithExtension(methodId), signer);

        // The extension survived verbatim into the wire proof.
        secured.GetProperty("proof").GetProperty("capabilityChain")[0].GetString()
            .Should().Be("urn:zcap:root:resource");

        pipeline.Verify(secured, publicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task TamperingTheExtensionField_FailsClosed_WithoutThrowing()
    {
        var (pipeline, signer, publicKey, methodId) = Setup();
        var secured = await pipeline.AddProofAsync(Document(), ProofOptionsWithExtension(methodId), signer);

        // Flip the capabilityChain value inside the proof — the signing input changes, so the
        // signature must no longer verify (and must NOT throw).
        var tampered = Fx.Mutate(secured, node =>
        {
            var proof = (JsonObject)node["proof"]!;
            proof["capabilityChain"] = new JsonArray("urn:zcap:root:ATTACKER");
        });

        var act = () => pipeline.Verify(tampered, publicKey);
        var result = act.Should().NotThrow().Subject;
        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public async Task DroppingTheExtensionField_FailsClosed()
    {
        var (pipeline, signer, publicKey, methodId) = Setup();
        var secured = await pipeline.AddProofAsync(Document(), ProofOptionsWithExtension(methodId), signer);

        // Removing the extension that was part of the signing input also breaks the signature.
        var stripped = Fx.Mutate(secured, node =>
        {
            var proof = (JsonObject)node["proof"]!;
            proof.Remove("capabilityChain");
        });

        var result = pipeline.Verify(stripped, publicKey);
        result.Verified.Should().BeFalse();
    }
}
