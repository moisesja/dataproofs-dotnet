using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Legacy.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using NSubstitute;
using Xunit;

namespace DataProofsDotnet.Legacy.Tests;

public sealed class Issue35ReviewTests
{
    [Theory]
    [InlineData(KeyType.Ed25519, false)]
    [InlineData(KeyType.P256, false)]
    [InlineData(KeyType.Ed25519, true)]
    [InlineData(KeyType.P256, true)]
    public async Task Create_ConfigPushedPastDepth64_MapsJsonExceptionBeforeSigning(KeyType keyType, bool throughPipeline)
    {
        var suite = Suite(keyType);
        var signer = Substitute.For<ISigner>();
        signer.KeyType.Returns(keyType);

        var thrown = await FluentActions.Invoking(() => Create(suite, Options(suite, 63), signer, throughPipeline))
            .Should().ThrowExactlyAsync<ProofGenerationException>()
            .WithMessage("The document or proof configuration could not be prepared for signing.");
        thrown.Which.InnerException.Should().BeOfType<JsonException>();
        await signer.DidNotReceive().SignAsync(Arg.Any<ReadOnlyMemory<byte>>(), Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(KeyType.Ed25519, false)]
    [InlineData(KeyType.P256, false)]
    [InlineData(KeyType.Ed25519, true)]
    [InlineData(KeyType.P256, true)]
    public async Task Create_ConfigAtCombinedDepth64_StillSignsAndVerifies(KeyType keyType, bool throughPipeline)
    {
        var suite = Suite(keyType);
        var key = Fx.SeedKey(1, keyType);
        var signer = Fx.Signer(key);
        var options = Options(suite, 62);
        var publicKey = PublicKeyMaterial.FromRaw(keyType, key.PublicKey);
        if (throughPipeline)
        {
            var pipeline = Pipeline(suite);
            var secured = await pipeline.AddProofAsync(Document(), options, signer);
            pipeline.Verify(secured, publicKey).Verified.Should().BeTrue();
        }
        else
        {
            var proof = await suite.CreateProofAsync(Document(), options, signer);
            suite.VerifyProof(Document(), proof, publicKey).Verified.Should().BeTrue();
        }
    }

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.P256)]
    public async Task Create_SignerFaultsKeepTheirOriginalInstance(KeyType keyType)
    {
        var suite = Suite(keyType);
        foreach (var fault in new Exception[] { new JsonException("signer"), new InvalidOperationException("signer"), new ArgumentException("signer"), new OperationCanceledException("signer") })
        {
            var signer = Substitute.For<ISigner>();
            signer.KeyType.Returns(keyType);
            signer.SignAsync(Arg.Any<ReadOnlyMemory<byte>>(), Arg.Any<CancellationToken>())
                .Returns(_ => Task.FromException<byte[]>(fault));
            var thrown = await Record.ExceptionAsync(() => Create(suite, Options(suite, 62), signer, true));
            thrown.Should().BeSameAs(fault);
        }
    }

    private static ICryptosuite Suite(KeyType keyType) => keyType == KeyType.Ed25519
        ? new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Jcs)
        : new EcdsaSecp256r1Signature2019Cryptosuite(LegacyCanonicalization.Jcs);

    private static JsonElement Document() => JsonDocument.Parse("{\"a\":1}").RootElement.Clone();

    private static DataIntegrityProof Options(ICryptosuite suite, int arrays) => new()
    {
        Cryptosuite = suite.Name,
        VerificationMethod = "did:example:alice#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
        AdditionalProperties = new Dictionary<string, JsonElement>
        {
            ["x"] = JsonDocument.Parse(new string('[', arrays) + "0" + new string(']', arrays)).RootElement.Clone(),
        },
    };

    private static DataIntegrityProofPipeline Pipeline(ICryptosuite suite)
    {
        var registry = new CryptosuiteRegistry();
        registry.Register(suite);
        return new DataIntegrityProofPipeline(registry);
    }

    private static async Task Create(ICryptosuite suite, DataIntegrityProof options, ISigner signer, bool throughPipeline)
    {
        if (throughPipeline)
        {
            _ = await Pipeline(suite).AddProofAsync(Document(), options, signer);
        }
        else
        {
            _ = await suite.CreateProofAsync(Document(), options, signer);
        }
    }
}
