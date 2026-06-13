using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Core.Tests.Unit;

/// <summary>FR-4: open cryptosuite registry; Core registers the JCS suites.</summary>
public class CryptosuiteRegistryTests
{
    [Fact]
    public void CreateDefault_RegistersTheJcsSuites()
    {
        var registry = CryptosuiteRegistry.CreateDefault();

        registry.RegisteredNames.Should().BeEquivalentTo(
            [EddsaJcs2022Cryptosuite.CryptosuiteName, EcdsaJcs2019Cryptosuite.CryptosuiteName]);
        registry.GetByName("eddsa-jcs-2022").Should().BeOfType<EddsaJcs2022Cryptosuite>();
        registry.GetByName("ecdsa-jcs-2019").Should().BeOfType<EcdsaJcs2019Cryptosuite>();
    }

    [Fact]
    public void NewRegistry_IsEmpty()
        => new CryptosuiteRegistry().RegisteredNames.Should().BeEmpty();

    [Fact]
    public void Register_AddsOpenEndedSuites_WithoutPipelineChanges()
    {
        var registry = new CryptosuiteRegistry();
        var suite = new FakeSuite("ecdsa-sd-2023");

        registry.Register(suite);

        registry.GetByName("ecdsa-sd-2023").Should().BeSameAs(suite);
    }

    [Fact]
    public void Register_ReplacesExistingSuiteOfSameName()
    {
        var registry = CryptosuiteRegistry.CreateDefault();
        var replacement = new FakeSuite(EddsaJcs2022Cryptosuite.CryptosuiteName);

        registry.Register(replacement);

        registry.GetByName(EddsaJcs2022Cryptosuite.CryptosuiteName).Should().BeSameAs(replacement);
        registry.RegisteredNames.Should().HaveCount(2);
    }

    [Fact]
    public void Register_RejectsNullAndUnnamedSuites()
    {
        var registry = new CryptosuiteRegistry();

        FluentActions.Invoking(() => registry.Register(null!)).Should().Throw<ArgumentNullException>();
        FluentActions.Invoking(() => registry.Register(new FakeSuite(""))).Should().Throw<ArgumentException>();
    }

    [Fact]
    public void GetByName_ReturnsNull_ForNullEmptyOrUnknownNames()
    {
        var registry = CryptosuiteRegistry.CreateDefault();

        registry.GetByName(null).Should().BeNull();
        registry.GetByName("").Should().BeNull();
        registry.GetByName("no-such-suite").Should().BeNull();
        registry.GetByName("EDDSA-JCS-2022").Should().BeNull("matching is ordinal, not case-insensitive");
    }

    private sealed class FakeSuite(string name) : ICryptosuite
    {
        public string Name => name;

        public Task<DataIntegrityProof> CreateProofAsync(
            JsonElement unsecuredDocument, DataIntegrityProof proofOptions, ISigner signer,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public ProofVerificationResult VerifyProof(
            JsonElement unsecuredDocument, DataIntegrityProof proof, DataProofsDotnet.PublicKeyMaterial publicKey)
            => throw new NotSupportedException();
    }
}
