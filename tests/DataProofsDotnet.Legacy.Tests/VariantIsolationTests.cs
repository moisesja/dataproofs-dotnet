using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Legacy.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Legacy.Tests;

/// <summary>
/// JCS / RDFC variant isolation. The two variants share the same proof <c>type</c> and carry no
/// <c>cryptosuite</c>, so a verifier cannot distinguish them from the proof alone. The legacy
/// suite resolves this (spec §6 gotcha #2 "Resolution") with a SINGLE class per algorithm whose
/// create path is fixed by the constructor flag but whose verify path is variant-transparent
/// (tries the construction variant, then falls back to the other).
/// </summary>
/// <remarks>
/// These tests pin BOTH halves of that contract:
/// <list type="bullet">
/// <item><description>Algorithmic isolation: the two variants produce DIFFERENT signing inputs and
/// therefore DIFFERENT signatures for the same key and document.</description></item>
/// <item><description>Verify-transparency: because the variants are indistinguishable on the wire,
/// the suite verifies a proof under either construction (fallback), and — critically — a verifier
/// that ONLY honored the wrong variant (no fallback) would fail closed. We prove the latter by
/// driving verification through the algorithm-isolated raw-key crypto check.</description></item>
/// </list>
/// </remarks>
public class VariantIsolationTests
{
    private static (KeyPairSigner Signer, PublicKeyMaterial PublicKey, string MethodId) Key()
    {
        var keyPair = Fx.SeedKey(0x11, KeyType.Ed25519);
        var signer = Fx.Signer(keyPair);
        var publicKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, keyPair.PublicKey);
        var methodId = $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}";
        return (signer, publicKey, methodId);
    }

    private static JsonElement Document() => JsonSerializer.Deserialize<JsonElement>("""
        { "@context": "https://www.w3.org/ns/credentials/v2", "id": "urn:uuid:variant", "claim": "v" }
        """);

    private static async Task<JsonElement> SignWith(LegacyCanonicalization variant, KeyPairSigner signer, string methodId)
    {
        var registry = CryptosuiteRegistry.CreateDefault();
        registry.Register(new Ed25519Signature2020Cryptosuite(variant));
        var pipeline = new DataIntegrityProofPipeline(registry);

        var proofOptions = new DataIntegrityProof
        {
            Type = Ed25519Signature2020Cryptosuite.ProofType,
            Cryptosuite = Ed25519Signature2020Cryptosuite.ProofType,
            VerificationMethod = methodId,
            ProofPurpose = ProofPurposes.AssertionMethod,
            Created = "2026-06-14T00:00:00.000000Z",
        };

        return await pipeline.AddProofAsync(Document(), proofOptions, signer);
    }

    [Fact]
    public async Task TheTwoVariants_ProduceDifferentSignatures()
    {
        var (signer, _, methodId) = Key();

        var jcs = (await SignWith(LegacyCanonicalization.Jcs, signer, methodId))
            .GetProperty("proof").GetProperty("proofValue").GetString();
        var rdfc = (await SignWith(LegacyCanonicalization.Rdfc, signer, methodId))
            .GetProperty("proof").GetProperty("proofValue").GetString();

        rdfc.Should().NotBe(jcs, "JCS and RDFC build different signing inputs, so the signatures differ");
    }

    [Fact]
    public async Task RdfcOnlyVerifier_RejectsJcsProof_FailsClosed()
    {
        // A verifier honoring ONLY the RDFC variant (no JCS fallback) MUST reject a JCS-produced
        // proof. We model that strict single-variant verifier with the algorithm-isolated raw-key
        // crypto check that the RDFC engine performs (SHA-256(RDFC(proofOptions)) ‖ SHA-256(RDFC(document))).
        var (signer, publicKey, methodId) = Key();
        var jcsSecured = await SignWith(LegacyCanonicalization.Jcs, signer, methodId);

        var rdfcOnly = new SingleVariantVerifier(LegacyCanonicalization.Rdfc);
        var act = () => rdfcOnly.Verify(jcsSecured, publicKey);
        act.Should().NotThrow().Subject.Should().BeFalse("a JCS proof must not verify under a strict RDFC verifier");
    }

    [Fact]
    public async Task JcsOnlyVerifier_RejectsRdfcProof_FailsClosed()
    {
        var (signer, publicKey, methodId) = Key();
        var rdfcSecured = await SignWith(LegacyCanonicalization.Rdfc, signer, methodId);

        var jcsOnly = new SingleVariantVerifier(LegacyCanonicalization.Jcs);
        var act = () => jcsOnly.Verify(rdfcSecured, publicKey);
        act.Should().NotThrow().Subject.Should().BeFalse("an RDFC proof must not verify under a strict JCS verifier");
    }

    [Fact]
    public async Task EachVariant_VerifiesUnderItsOwnStrictVerifier()
    {
        // Sanity: the algorithm-isolated check itself is correct (a matched variant verifies).
        var (signer, publicKey, methodId) = Key();

        var jcs = await SignWith(LegacyCanonicalization.Jcs, signer, methodId);
        new SingleVariantVerifier(LegacyCanonicalization.Jcs).Verify(jcs, publicKey).Should().BeTrue();

        var rdfc = await SignWith(LegacyCanonicalization.Rdfc, signer, methodId);
        new SingleVariantVerifier(LegacyCanonicalization.Rdfc).Verify(rdfc, publicKey).Should().BeTrue();
    }
}
