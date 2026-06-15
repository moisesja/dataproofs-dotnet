using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Legacy.Tests.TestSupport;
using FluentAssertions;
using NetCid;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Legacy.Tests;

/// <summary>
/// The interop-critical acceptance criterion: a proof produced by an INDEPENDENT stack
/// (zcap-dotnet) under the legacy <c>Ed25519Signature2020</c> convention must verify under the
/// DataProofsDotnet.Legacy suite, and — because Ed25519 is deterministic — re-creating that proof
/// from the same fixed seed and JCS input must reproduce zcap's <c>proofValue</c> byte-for-byte.
/// The vector is vendored under <c>tests/fixtures/legacy/zcap/</c> (see PROVENANCE.md).
/// </summary>
public class CrossStackByteIdentityTests
{
    private static readonly string[] Fixture = ["legacy", "zcap", "ed25519-signature-2020-delegated.json"];

    // The exact golden proofValue zcap issues for the fixed seed + fixed `created`.
    private const string ZcapProofValue =
        "z5vKNNJVDziWyjoSSxFCNXJ6ZL4FSfrA7TbWDwhkBmkHCgN4448kTMJTUoK3pW35dNrGbyWP1moBSCb4nsYAc5fx8";

    private const string ZcapPublicKeyMultibase = "z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7";

    private static DataIntegrityProofPipeline PipelineWithEd25519(LegacyCanonicalization variant)
    {
        var registry = CryptosuiteRegistry.CreateDefault();
        registry.Register(new Ed25519Signature2020Cryptosuite(variant));
        return new DataIntegrityProofPipeline(registry);
    }

    /// <summary>
    /// The verification key is obtained ONLY from the proof's <c>verificationMethod</c> did:key
    /// fragment (decoded as a multikey), exactly as a real verifier with no out-of-band key would.
    /// </summary>
    private static PublicKeyMaterial KeyFromVerificationMethod(JsonElement proof)
    {
        var method = proof.GetProperty("verificationMethod").GetString()!;
        var multibase = method[(method.IndexOf('#') + 1)..]; // fragment after '#'
        multibase.Should().Be(ZcapPublicKeyMultibase, "the did:key fragment IS the public multikey");
        return PublicKeyMaterial.FromMultikey(multibase);
    }

    [Fact]
    public void ZcapIssuedProof_Verifies_ThroughPipeline_RawKeyPath()
    {
        var secured = Fx.Json(Fixture);
        var publicKey = KeyFromVerificationMethod(secured.GetProperty("proof"));

        var pipeline = PipelineWithEd25519(LegacyCanonicalization.Jcs);
        var result = pipeline.Verify(secured, publicKey);

        result.Verified.Should().BeTrue("the zcap-produced Ed25519Signature2020 proof must verify under the legacy suite");
        result.ProofResults.Should().ContainSingle().Which.Verified.Should().BeTrue();
    }

    [Fact]
    public async Task ZcapIssuedProof_Verifies_ThroughPipeline_ResolverPath()
    {
        var secured = Fx.Json(Fixture);
        var proof = secured.GetProperty("proof");
        var methodId = proof.GetProperty("verificationMethod").GetString()!;
        var publicKey = KeyFromVerificationMethod(proof);

        var pipeline = PipelineWithEd25519(LegacyCanonicalization.Jcs);
        var result = await pipeline.VerifyAsync(
            secured,
            Fx.SingleMethodResolver(methodId, publicKey, ProofPurposes.CapabilityDelegation),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.CapabilityDelegation });

        result.Verified.Should().BeTrue();
        result.ProofResults.Should().ContainSingle().Which.Verified.Should().BeTrue();
    }

    [Fact]
    public void GoldenSeed_DerivesZcapPublicKey()
    {
        // The fixture's verificationMethod public key must be the one the fixed seed derives —
        // proving our key derivation matches zcap's (and is byte-stable for the create test).
        var signer = Fx.Signer(Fx.GoldenSeedKey());
        signer.MultibasePublicKey.Should().Be(ZcapPublicKeyMultibase);
    }

    [Fact]
    public async Task RecreatedProof_ProofValue_IsByteIdenticalToZcap()
    {
        // Reconstruct the UNSIGNED document (fixture minus proof) and the proof options
        // (proof minus proofValue), then re-sign with the same fixed seed via the pipeline.
        var secured = Fx.Json(Fixture);
        var unsignedNode = JsonObject.Create(secured)!;
        unsignedNode.Remove("proof");
        var unsigned = Fx.ToElement(unsignedNode);

        var proofOptions = secured.GetProperty("proof")
            .Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!
            with
            {
                ProofValue = null,
                // Name the suite so AddProofAsync dispatches by cryptosuite; the wire shape
                // emits cryptosuite=null, exactly matching zcap.
                Cryptosuite = Ed25519Signature2020Cryptosuite.ProofType,
            };

        var pipeline = PipelineWithEd25519(LegacyCanonicalization.Jcs);
        var resecured = await pipeline.AddProofAsync(unsigned, proofOptions, Fx.Signer(Fx.GoldenSeedKey()));

        var recreated = resecured.GetProperty("proof").GetProperty("proofValue").GetString();
        recreated.Should().Be(
            ZcapProofValue,
            "Ed25519 over the JCS-nested signing input must be byte-identical to the zcap-issued proof");

        // And the whole secured document is structurally identical to the vendored vector.
        JsonElement.DeepEquals(resecured, secured).Should().BeTrue(
            "the re-secured document (including cryptosuite-less proof) must equal the zcap vector");
    }

    [Fact]
    public void ZcapProofValue_IsBase58Btc_AndDecodesTo64Bytes()
    {
        Multibase.TryDecode(ZcapProofValue, out var bytes, out var encoding).Should().BeTrue();
        encoding.Should().Be(MultibaseEncoding.Base58Btc);
        bytes.Should().HaveCount(64, "an Ed25519 signature is 64 raw bytes");
    }
}
