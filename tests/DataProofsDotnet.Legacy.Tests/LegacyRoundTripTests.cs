using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Legacy.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Legacy.Tests;

/// <summary>
/// Pipeline round-trip coverage for both legacy suites
/// (<c>Ed25519Signature2020</c>, <c>EcdsaSecp256r1Signature2019</c>) × both canonicalization
/// variants (<see cref="LegacyCanonicalization.Jcs"/>, <see cref="LegacyCanonicalization.Rdfc"/>).
/// The suite is registered on <see cref="CryptosuiteRegistry.CreateDefault"/>; the proof options
/// name the suite so creation dispatches by <c>cryptosuite</c>; the emitted proof is asserted to
/// carry the legacy <c>type</c>, NO <c>cryptosuite</c>, and a base58-btc <c>proofValue</c>; then
/// verification (raw-key and resolver paths) succeeds — dispatching by <c>type</c> alone.
/// </summary>
public class LegacyRoundTripTests
{
    // RDFC signs only what the contexts define (issue #36). ed25519-2020/v1 defines the
    // Ed25519Signature2020 proof terms; EcdsaSecp256r1Signature2019 has no published context, so
    // its proof terms, like the example's own, are carried by undefined-terms/v2 (VCDM 2.0 §5.2).
    private const string Contexts = """
        "https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/undefined-terms/v2"
        """;

    private const string Ed25519Contexts = """
        "https://www.w3.org/ns/credentials/v2", "https://w3id.org/security/suites/ed25519-2020/v1",
        "https://www.w3.org/ns/credentials/undefined-terms/v2"
        """;

    public static TheoryData<string, KeyType, LegacyCanonicalization> Matrix() => new()
    {
        { Ed25519Signature2020Cryptosuite.ProofType, KeyType.Ed25519, LegacyCanonicalization.Jcs },
        { Ed25519Signature2020Cryptosuite.ProofType, KeyType.Ed25519, LegacyCanonicalization.Rdfc },
        { EcdsaSecp256r1Signature2019Cryptosuite.ProofType, KeyType.P256, LegacyCanonicalization.Jcs },
        { EcdsaSecp256r1Signature2019Cryptosuite.ProofType, KeyType.P256, LegacyCanonicalization.Rdfc },
    };

    private static ICryptosuite Suite(string legacyType, LegacyCanonicalization variant)
        => legacyType == Ed25519Signature2020Cryptosuite.ProofType
            ? new Ed25519Signature2020Cryptosuite(variant)
            : new EcdsaSecp256r1Signature2019Cryptosuite(variant);

    private static (DataIntegrityProofPipeline Pipeline, KeyPairSigner Signer, PublicKeyMaterial PublicKey, string MethodId)
        Setup(string legacyType, KeyType keyType, LegacyCanonicalization variant)
    {
        var registry = CryptosuiteRegistry.CreateDefault();
        registry.Register(Suite(legacyType, variant));
        var pipeline = new DataIntegrityProofPipeline(registry);

        var keyPair = Fx.SeedKey(0x07, keyType);
        var signer = Fx.Signer(keyPair);
        var publicKey = PublicKeyMaterial.FromRaw(keyType, keyPair.PublicKey);
        var methodId = $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}";
        return (pipeline, signer, publicKey, methodId);
    }

    private static JsonElement Document(string legacyType) => JsonSerializer.Deserialize<JsonElement>($$"""
        {
          "@context": [{{(legacyType == Ed25519Signature2020Cryptosuite.ProofType ? Ed25519Contexts : Contexts)}}],
          "id": "urn:uuid:legacy-roundtrip-subject",
          "type": ["VerifiableCredential", "ExampleCredential"],
          "issuer": "did:example:issuer",
          "credentialSubject": { "id": "did:example:subject", "claim": "value" }
        }
        """);

    [Theory]
    [MemberData(nameof(Matrix))]
    public async Task AddProof_EmitsLegacyShape_AndVerifies_RawKeyPath(
        string legacyType, KeyType keyType, LegacyCanonicalization variant)
    {
        var (pipeline, signer, publicKey, methodId) = Setup(legacyType, keyType, variant);

        var proofOptions = new DataIntegrityProof
        {
            Type = legacyType,
            Cryptosuite = legacyType, // names the suite for AddProofAsync dispatch (GetByName)
            VerificationMethod = methodId,
            ProofPurpose = ProofPurposes.AssertionMethod,
            Created = "2026-06-14T00:00:00.000000Z",
        };

        var secured = await pipeline.AddProofAsync(Document(legacyType), proofOptions, signer);

        var proof = secured.GetProperty("proof");
        proof.GetProperty("type").GetString().Should().Be(legacyType);
        proof.TryGetProperty("cryptosuite", out _).Should().BeFalse("the legacy wire shape carries no cryptosuite");
        var proofValue = proof.GetProperty("proofValue").GetString();
        proofValue.Should().StartWith("z", "the legacy proofValue is base58-btc multibase");

        // Verify dispatches by type alone (no cryptosuite on the wire).
        var result = pipeline.Verify(secured, publicKey);
        result.Verified.Should().BeTrue();
        result.ProofResults.Should().ContainSingle().Which.Verified.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public async Task AddProof_Verifies_ResolverPath(
        string legacyType, KeyType keyType, LegacyCanonicalization variant)
    {
        var (pipeline, signer, publicKey, methodId) = Setup(legacyType, keyType, variant);

        var proofOptions = new DataIntegrityProof
        {
            Type = legacyType,
            Cryptosuite = legacyType,
            VerificationMethod = methodId,
            ProofPurpose = ProofPurposes.AssertionMethod,
            Created = "2026-06-14T00:00:00.000000Z",
        };

        var secured = await pipeline.AddProofAsync(Document(legacyType), proofOptions, signer);

        var result = await pipeline.VerifyAsync(
            secured,
            Fx.SingleMethodResolver(methodId, publicKey),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeTrue();
        result.ProofResults.Should().ContainSingle().Which.Verified.Should().BeTrue();
    }
}
