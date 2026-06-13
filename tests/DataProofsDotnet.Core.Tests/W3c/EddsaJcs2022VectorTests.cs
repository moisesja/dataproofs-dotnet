using System.Text;
using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.Core.Tests.TestSupport;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCid;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Core.Tests.W3c;

/// <summary>
/// AC-1 steps 1 and 2 for <c>eddsa-jcs-2022</c> against the vendored W3C
/// DI EdDSA Cryptosuites 1.0 (REC-20250515) test vectors
/// (<c>tests/fixtures/w3c/vc-di-eddsa/TestVectors/eddsa-jcs-2022/</c>).
/// </summary>
public class EddsaJcs2022VectorTests
{
    private static readonly string[] Root = ["w3c", "vc-di-eddsa", "TestVectors"];

    private static string[] In(params string[] parts) => [.. Root, .. parts];

    private static (string MethodId, string PublicKeyMultibase, KeyPair KeyPair) FixtureKey()
    {
        var pair = Fx.Json(In("keyPair.json"));
        var publicKeyMultibase = pair.GetProperty("publicKeyMultibase").GetString()!;
        var keyPair = Fx.SecretKey(pair.GetProperty("privateKeyMultibase").GetString()!);
        var methodId = $"did:key:{publicKeyMultibase}#{publicKeyMultibase}";
        return (methodId, publicKeyMultibase, keyPair);
    }

    private static readonly DataIntegrityProofPipeline Pipeline = new();

    // ----------------------------------------------------------- step 1: verification

    [Fact]
    public async Task SignedVector_Verifies_OnResolverPath()
    {
        var signed = Fx.Json(In("eddsa-jcs-2022", "signedJCS.json"));
        var (methodId, publicKeyMultibase, _) = FixtureKey();

        var result = await Pipeline.VerifyAsync(
            signed,
            Fx.SingleMethodResolver(methodId, publicKeyMultibase),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeTrue();
        result.ProofResults.Should().ContainSingle().Which.Verified.Should().BeTrue();
    }

    [Fact]
    public void SignedVector_Verifies_OnRawKeyPath()
    {
        var signed = Fx.Json(In("eddsa-jcs-2022", "signedJCS.json"));
        var (_, publicKeyMultibase, _) = FixtureKey();

        var result = Pipeline.Verify(signed, PublicKeyMaterial.FromMultikey(publicKeyMultibase));

        result.Verified.Should().BeTrue();
    }

    [Fact]
    public void TamperedDocument_FailsWithProofVerificationError_WithoutThrowing()
    {
        var signed = Fx.Json(In("eddsa-jcs-2022", "signedJCS.json"));
        var (_, publicKeyMultibase, _) = FixtureKey();
        var tampered = Fx.Mutate(signed, node => node["name"] = "Tampered Credential");

        var result = Pipeline.Verify(tampered, PublicKeyMaterial.FromMultikey(publicKeyMultibase));

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public void WrongKey_FailsWithProofVerificationError_WithoutThrowing()
    {
        var signed = Fx.Json(In("eddsa-jcs-2022", "signedJCS.json"));
        var wrongKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, Fx.SeedKey(0x01).PublicKey);

        var result = Pipeline.Verify(signed, wrongKey);

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public void ProofPurposeFieldMismatch_FailsWithProofVerificationError()
    {
        var signed = Fx.Json(In("eddsa-jcs-2022", "signedJCS.json"));
        var (_, publicKeyMultibase, _) = FixtureKey();

        var result = Pipeline.Verify(
            signed,
            PublicKeyMaterial.FromMultikey(publicKeyMultibase),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.Authentication });

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    // ------------------------------------------- step 2: byte-identical re-creation

    [Fact]
    public async Task RecreatedProof_ProofValue_IsByteIdenticalToVector()
    {
        var unsigned = Fx.Json(In("unsigned.json"));
        var proofOptions = Fx.Json(In("eddsa-jcs-2022", "proofConfigJCS.json"))
            .Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
        var (_, _, keyPair) = FixtureKey();

        var secured = await Pipeline.AddProofAsync(unsigned, proofOptions, Fx.Signer(keyPair));

        var proofValue = secured.GetProperty("proof").GetProperty("proofValue").GetString();
        proofValue.Should().Be(Fx.Text(In("eddsa-jcs-2022", "sigBTC58JCS.txt")));
        proofValue.Should().Be(
            Fx.Json(In("eddsa-jcs-2022", "signedJCS.json")).GetProperty("proof").GetProperty("proofValue").GetString());

        // The full secured document is structurally identical to the expected vector.
        JsonElement.DeepEquals(secured, Fx.Json(In("eddsa-jcs-2022", "signedJCS.json"))).Should().BeTrue();
    }

    // ------------------------------ intermediate determinism (canonical form, hashes)

    [Fact]
    public void CanonicalDocument_MatchesVector()
    {
        var unsigned = Fx.Json(In("unsigned.json"));

        var canonical = JcsCanonicalizer.Canonicalize(unsigned);

        Encoding.UTF8.GetString(canonical).Should().Be(Fx.Text(In("eddsa-jcs-2022", "canonDocJCS.txt")));
    }

    [Fact]
    public void CanonicalProofConfig_MatchesVector_AfterModelRoundTrip()
    {
        // The proof config is round-tripped through the FR-1 model exactly as the suite
        // does it, proving the model neither drops nor adds members.
        var proofConfig = Fx.Json(In("eddsa-jcs-2022", "proofConfigJCS.json"))
            .Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;

        var canonical = JcsCanonicalizer.Canonicalize(
            JsonSerializer.SerializeToElement(proofConfig, DataProofsJsonOptions.Default));

        Encoding.UTF8.GetString(canonical).Should().Be(Fx.Text(In("eddsa-jcs-2022", "proofCanonJCS.txt")));
    }

    [Fact]
    public void HashData_MatchesVector()
    {
        var docHash = Hash.Sha256(JcsCanonicalizer.Canonicalize(Fx.Json(In("unsigned.json"))));
        var proofConfig = Fx.Json(In("eddsa-jcs-2022", "proofConfigJCS.json"))
            .Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
        var proofHash = Hash.Sha256(JcsCanonicalizer.Canonicalize(
            JsonSerializer.SerializeToElement(proofConfig, DataProofsJsonOptions.Default)));

        docHash.Should().Equal(Fx.HexBytes(In("eddsa-jcs-2022", "docHashJCS.txt")));
        proofHash.Should().Equal(Fx.HexBytes(In("eddsa-jcs-2022", "proofHashJCS.txt")));

        // hashData = hash(canonical proof config) ‖ hash(canonical document).
        byte[] hashData = [.. proofHash, .. docHash];
        hashData.Should().Equal(Fx.HexBytes(In("eddsa-jcs-2022", "combinedHashJCS.txt")));
    }

    [Fact]
    public void SignatureVector_DecodesFromProofValue_AndVerifiesOverHashData()
    {
        var (_, publicKeyMultibase, _) = FixtureKey();
        var signature = Fx.HexBytes(In("eddsa-jcs-2022", "sigHexJCS.txt"));
        var hashData = Fx.HexBytes(In("eddsa-jcs-2022", "combinedHashJCS.txt"));

        Multibase.TryDecode(Fx.Text(In("eddsa-jcs-2022", "sigBTC58JCS.txt")), out var decoded, out var encoding)
            .Should().BeTrue();
        encoding.Should().Be(MultibaseEncoding.Base58Btc);
        decoded.Should().Equal(signature);

        var publicKey = PublicKeyMaterial.FromMultikey(publicKeyMultibase);
        Fx.Crypto.Verify(KeyType.Ed25519, publicKey.KeyBytes.Span, hashData, signature).Should().BeTrue();
    }
}
