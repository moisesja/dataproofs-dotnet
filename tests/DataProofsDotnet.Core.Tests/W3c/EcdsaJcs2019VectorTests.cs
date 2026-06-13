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
/// AC-1 steps 1 and 3 for <c>ecdsa-jcs-2019</c> (P-256/SHA-256 and P-384/SHA-384)
/// against the vendored W3C DI ECDSA Cryptosuites 1.0 (REC-20250515) vectors
/// (<c>tests/fixtures/w3c/vc-di-ecdsa/spec/ecdsa-jcs-2019-*</c>) and the
/// independently generated test-suite credentials
/// (<c>tests/fixtures/w3c/vc-di-ecdsa/test-suite/extracted/</c>).
/// </summary>
public class EcdsaJcs2019VectorTests
{
    private static readonly string[] Root = ["w3c", "vc-di-ecdsa", "spec"];
    private static readonly DataIntegrityProofPipeline Pipeline = new();

    private static string[] In(params string[] parts) => [.. Root, .. parts];

    public static TheoryData<string, string, string> Curves => new()
    {
        // suite directory, file suffix, key-pair file
        { "ecdsa-jcs-2019-p256", "JCSECDSAP256", "p256KeyPair.json" },
        { "ecdsa-jcs-2019-p384", "JCSECDSAP384", "p384KeyPair.json" },
    };

    private static (string MethodId, string PublicKeyMultibase, KeyPair KeyPair) FixtureKey(string keyFile)
    {
        var pair = Fx.Json(In(keyFile));
        var publicKeyMultibase = pair.GetProperty("publicKeyMultibase").GetString()!;
        var keyPair = Fx.SecretKey(pair.GetProperty("secretKeyMultibase").GetString()!);
        var methodId = $"did:key:{publicKeyMultibase}#{publicKeyMultibase}";
        return (methodId, publicKeyMultibase, keyPair);
    }

    private static byte[] SuiteHash(KeyType keyType, ReadOnlySpan<byte> data)
        => keyType == KeyType.P384 ? Hash.Sha384(data) : Hash.Sha256(data);

    // ----------------------------------------------------------- step 1: verification

    [Theory]
    [MemberData(nameof(Curves))]
    public async Task SignedVector_Verifies_OnResolverPath(string suiteDir, string suffix, string keyFile)
    {
        var signed = Fx.Json(In(suiteDir, $"signed{suffix}.json"));
        var (methodId, publicKeyMultibase, _) = FixtureKey(keyFile);

        var result = await Pipeline.VerifyAsync(
            signed,
            Fx.SingleMethodResolver(methodId, publicKeyMultibase),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeTrue();
        result.ProofResults.Should().ContainSingle().Which.Verified.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void SignedVector_Verifies_OnRawKeyPath(string suiteDir, string suffix, string keyFile)
    {
        var signed = Fx.Json(In(suiteDir, $"signed{suffix}.json"));
        var (_, publicKeyMultibase, _) = FixtureKey(keyFile);

        Pipeline.Verify(signed, PublicKeyMaterial.FromMultikey(publicKeyMultibase)).Verified.Should().BeTrue();
    }

    [Theory]
    [InlineData("signed-credential-ecdsa-jcs-2019-p256.json", "p256KeyPair.json")]
    [InlineData("signed-credential-ecdsa-jcs-2019-p384.json", "p384KeyPair.json")]
    public async Task TestSuiteCredential_Verifies_OnResolverPath(string file, string keyFile)
    {
        var signed = Fx.Json("w3c", "vc-di-ecdsa", "test-suite", "extracted", file);
        var (methodId, publicKeyMultibase, _) = FixtureKey(keyFile);

        var result = await Pipeline.VerifyAsync(
            signed,
            Fx.SingleMethodResolver(methodId, publicKeyMultibase),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void TamperedDocument_FailsWithProofVerificationError_WithoutThrowing(string suiteDir, string suffix, string keyFile)
    {
        var signed = Fx.Json(In(suiteDir, $"signed{suffix}.json"));
        var (_, publicKeyMultibase, _) = FixtureKey(keyFile);
        var tampered = Fx.Mutate(signed, node => node["name"] = "Tampered Credential");

        var result = Pipeline.Verify(tampered, PublicKeyMaterial.FromMultikey(publicKeyMultibase));

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Theory]
    [InlineData("ecdsa-jcs-2019-p256", "JCSECDSAP256", KeyType.P256)]
    [InlineData("ecdsa-jcs-2019-p384", "JCSECDSAP384", KeyType.P384)]
    public void WrongKey_FailsWithProofVerificationError_WithoutThrowing(string suiteDir, string suffix, KeyType keyType)
    {
        var signed = Fx.Json(In(suiteDir, $"signed{suffix}.json"));
        var wrongKey = PublicKeyMaterial.FromRaw(keyType, Fx.SeedKey(0x01, keyType).PublicKey);

        var result = Pipeline.Verify(signed, wrongKey);

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void ProofPurposeFieldMismatch_FailsWithProofVerificationError(string suiteDir, string suffix, string keyFile)
    {
        var signed = Fx.Json(In(suiteDir, $"signed{suffix}.json"));
        var (_, publicKeyMultibase, _) = FixtureKey(keyFile);

        var result = Pipeline.Verify(
            signed,
            PublicKeyMaterial.FromMultikey(publicKeyMultibase),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.Authentication });

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    // -------------------------- step 3: round-trip creation (signature is randomized)

    [Theory]
    [MemberData(nameof(Curves))]
    public async Task CreatedProof_RoundTrips_ThroughResolverAndRawKeyPaths(string suiteDir, string suffix, string keyFile)
    {
        var unsigned = Fx.Json(In("unsigned.json"));
        var proofOptions = Fx.Json(In(suiteDir, $"proofConfig{suffix}.json"))
            .Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
        var (methodId, publicKeyMultibase, keyPair) = FixtureKey(keyFile);

        var secured = await Pipeline.AddProofAsync(unsigned, proofOptions, Fx.Signer(keyPair));

        // The proofValue is randomized; everything else must match the expected vector.
        var expected = Fx.Mutate(
            Fx.Json(In(suiteDir, $"signed{suffix}.json")),
            node => ((System.Text.Json.Nodes.JsonObject)node["proof"]!).Remove("proofValue"));
        var actual = Fx.Mutate(
            secured,
            node => ((System.Text.Json.Nodes.JsonObject)node["proof"]!).Remove("proofValue"));
        JsonElement.DeepEquals(actual, expected).Should().BeTrue();

        Pipeline.Verify(secured, PublicKeyMaterial.FromMultikey(publicKeyMultibase)).Verified.Should().BeTrue();
        (await Pipeline.VerifyAsync(
            secured,
            Fx.SingleMethodResolver(methodId, publicKeyMultibase),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod }))
            .Verified.Should().BeTrue();
    }

    // ---------------------- step 3: intermediate determinism (canonical form, hashes)

    [Theory]
    [MemberData(nameof(Curves))]
    public void CanonicalDocument_MatchesVector(string suiteDir, string suffix, string keyFile)
    {
        _ = keyFile;
        var canonical = JcsCanonicalizer.Canonicalize(Fx.Json(In("unsigned.json")));

        Encoding.UTF8.GetString(canonical).Should().Be(Fx.Text(In(suiteDir, $"canonDoc{suffix}.txt")));
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void CanonicalProofConfig_MatchesVector_AfterModelRoundTrip(string suiteDir, string suffix, string keyFile)
    {
        _ = keyFile;
        var proofConfig = Fx.Json(In(suiteDir, $"proofConfig{suffix}.json"))
            .Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;

        var canonical = JcsCanonicalizer.Canonicalize(
            JsonSerializer.SerializeToElement(proofConfig, DataProofsJsonOptions.Default));

        Encoding.UTF8.GetString(canonical).Should().Be(Fx.Text(In(suiteDir, $"proofCanon{suffix}.txt")));
    }

    [Theory]
    [InlineData("ecdsa-jcs-2019-p256", "JCSECDSAP256", KeyType.P256)]
    [InlineData("ecdsa-jcs-2019-p384", "JCSECDSAP384", KeyType.P384)]
    public void HashData_MatchesVector(string suiteDir, string suffix, KeyType keyType)
    {
        var docHash = SuiteHash(keyType, JcsCanonicalizer.Canonicalize(Fx.Json(In("unsigned.json"))));
        var proofConfig = Fx.Json(In(suiteDir, $"proofConfig{suffix}.json"))
            .Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
        var proofHash = SuiteHash(keyType, JcsCanonicalizer.Canonicalize(
            JsonSerializer.SerializeToElement(proofConfig, DataProofsJsonOptions.Default)));

        docHash.Should().Equal(Fx.HexBytes(In(suiteDir, $"docHash{suffix}.txt")));
        proofHash.Should().Equal(Fx.HexBytes(In(suiteDir, $"proofHash{suffix}.txt")));

        byte[] hashData = [.. proofHash, .. docHash];
        hashData.Should().Equal(Fx.HexBytes(In(suiteDir, $"combinedHash{suffix}.txt")));
    }

    [Theory]
    [InlineData("ecdsa-jcs-2019-p256", "JCSECDSAP256", "p256KeyPair.json", KeyType.P256)]
    [InlineData("ecdsa-jcs-2019-p384", "JCSECDSAP384", "p384KeyPair.json", KeyType.P384)]
    public void SignatureVector_DecodesFromProofValue_AndVerifiesOverHashData(
        string suiteDir, string suffix, string keyFile, KeyType keyType)
    {
        var (_, publicKeyMultibase, _) = FixtureKey(keyFile);
        var signature = Fx.HexBytes(In(suiteDir, $"sigHex{suffix}.txt"));
        var hashData = Fx.HexBytes(In(suiteDir, $"combinedHash{suffix}.txt"));

        Multibase.TryDecode(Fx.Text(In(suiteDir, $"sigBTC58{suffix}.txt")), out var decoded, out var encoding)
            .Should().BeTrue();
        encoding.Should().Be(MultibaseEncoding.Base58Btc);
        decoded.Should().Equal(signature);

        // The W3C wire form is IEEE P1363 fixed-width r ‖ s.
        signature.Length.Should().Be(keyType == KeyType.P384 ? 96 : 64);
        var publicKey = PublicKeyMaterial.FromMultikey(publicKeyMultibase);
        Fx.Crypto.Verify(keyType, publicKey.KeyBytes.Span, hashData, signature, EcdsaSignatureFormat.IeeeP1363)
            .Should().BeTrue();
    }
}
