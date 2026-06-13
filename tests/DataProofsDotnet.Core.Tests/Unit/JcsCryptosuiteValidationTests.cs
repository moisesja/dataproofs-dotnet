using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.Core.Tests.TestSupport;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Core.Tests.Unit;

/// <summary>FR-5: suite-level option validation and deterministic re-signing.</summary>
public class JcsCryptosuiteValidationTests
{
    private static JsonElement Doc() => JsonDocument.Parse(
        """{"@context":["https://www.w3.org/ns/credentials/v2"],"k":"v"}""").RootElement.Clone();

    private static DataIntegrityProof Options(string cryptosuite) => new()
    {
        Cryptosuite = cryptosuite,
        Created = "2026-01-01T00:00:00Z",
        VerificationMethod = "did:example:alice#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    [Fact]
    public async Task EddsaSuite_RejectsMismatchedCryptosuiteName()
    {
        var suite = new EddsaJcs2022Cryptosuite();

        var act = () => suite.CreateProofAsync(Doc(), Options("ecdsa-jcs-2019"), Fx.Signer(Fx.SeedKey(0x01)));

        await act.Should().ThrowAsync<ProofGenerationException>();
    }

    [Fact]
    public async Task EddsaSuite_FillsCryptosuite_WhenOptionsOmitIt()
    {
        var suite = new EddsaJcs2022Cryptosuite();

        var proof = await suite.CreateProofAsync(
            Doc(), Options(null!) with { Cryptosuite = null }, Fx.Signer(Fx.SeedKey(0x01)));

        proof.Cryptosuite.Should().Be(EddsaJcs2022Cryptosuite.CryptosuiteName);
        proof.ProofValue.Should().StartWith("z");
    }

    [Fact]
    public async Task CreatedProof_CopiesDocumentContext_AndExcludesProofValueFromConfig()
    {
        var suite = new EddsaJcs2022Cryptosuite();

        var proof = await suite.CreateProofAsync(Doc(), Options("eddsa-jcs-2022"), Fx.Signer(Fx.SeedKey(0x01)));

        proof.Context.Should().NotBeNull();
        JsonElement.DeepEquals(proof.Context!.Value, Doc().GetProperty("@context")).Should().BeTrue();
        proof.ProofValue.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task EddsaSigning_IsDeterministic_ByteIdenticalAcrossRuns()
    {
        // NFR-5: identical inputs + key + suite => byte-identical proofs.
        var pipeline = new DataIntegrityProofPipeline();
        var first = await pipeline.AddProofAsync(Doc(), Options("eddsa-jcs-2022"), Fx.Signer(Fx.SeedKey(0x01)));
        var second = await pipeline.AddProofAsync(Doc(), Options("eddsa-jcs-2022"), Fx.Signer(Fx.SeedKey(0x01)));

        Fx.Compact(first).Should().Be(Fx.Compact(second));
    }

    [Fact]
    public async Task EcdsaSuite_SupportsBothNistCurves_AndRejectsOthers()
    {
        var suite = new EcdsaJcs2019Cryptosuite();

        var p256 = await suite.CreateProofAsync(
            Doc(), Options("ecdsa-jcs-2019"), Fx.Signer(Fx.SeedKey(0x01, KeyType.P256)));
        var p384 = await suite.CreateProofAsync(
            Doc(), Options("ecdsa-jcs-2019"), Fx.Signer(Fx.SeedKey(0x01, KeyType.P384)));

        p256.ProofValue.Should().StartWith("z");
        p384.ProofValue.Should().StartWith("z");

        var ed25519 = () => suite.CreateProofAsync(
            Doc(), Options("ecdsa-jcs-2019"), Fx.Signer(Fx.SeedKey(0x01)));
        await ed25519.Should().ThrowAsync<ProofGenerationException>();
    }

    [Fact]
    public async Task EcdsaProofValue_DecodesToFixedWidthP1363()
    {
        var suite = new EcdsaJcs2019Cryptosuite();

        var p256 = await suite.CreateProofAsync(
            Doc(), Options("ecdsa-jcs-2019"), Fx.Signer(Fx.SeedKey(0x01, KeyType.P256)));
        var p384 = await suite.CreateProofAsync(
            Doc(), Options("ecdsa-jcs-2019"), Fx.Signer(Fx.SeedKey(0x01, KeyType.P384)));

        NetCid.Multibase.TryDecode(p256.ProofValue!, out var sig256, out _).Should().BeTrue();
        NetCid.Multibase.TryDecode(p384.ProofValue!, out var sig384, out _).Should().BeTrue();
        sig256.Length.Should().Be(64, "P-256 P1363 is r(32) ‖ s(32)");
        sig384.Length.Should().Be(96, "P-384 P1363 is r(48) ‖ s(48)");
    }

    [Fact]
    public void VerifyProof_NullArguments_Throw()
    {
        var suite = new EddsaJcs2022Cryptosuite();
        var key = PublicKeyMaterial.FromRaw(KeyType.Ed25519, Fx.SeedKey(0x01).PublicKey);

        FluentActions.Invoking(() => suite.VerifyProof(Doc(), null!, key)).Should().Throw<ArgumentNullException>();
        FluentActions.Invoking(() => suite.VerifyProof(Doc(), Options("eddsa-jcs-2022"), null!))
            .Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void VerifyProof_WrongKeyTypeForSuite_FailsAsResult()
    {
        var suite = new EddsaJcs2022Cryptosuite();
        var p256Key = PublicKeyMaterial.FromRaw(KeyType.P256, Fx.SeedKey(0x01, KeyType.P256).PublicKey);

        var result = suite.VerifyProof(
            Doc(),
            Options("eddsa-jcs-2022") with { ProofValue = "z3FXQ" },
            p256Key);

        result.Verified.Should().BeFalse();
        result.Problems.Single().Code.Should().Be(ProofProblemCodes.ProofVerificationError);
    }
}
