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

    [Fact]
    public void GetByProofType_ResolvesLegacySuiteByDeclaredType()
    {
        var registry = new CryptosuiteRegistry();
        var legacy = new FakeSuite("Ed25519Signature2020", proofTypes: ["Ed25519Signature2020"]);

        registry.Register(legacy);

        registry.GetByProofType("Ed25519Signature2020").Should().BeSameAs(legacy);
    }

    [Fact]
    public void GetByProofType_ReturnsNull_ForDefaultTypeNullEmptyAndUnknown()
    {
        // Default-type suites (the JCS suites) are dispatched by cryptosuite name, never by
        // type, so they are deliberately absent from the type index.
        var registry = CryptosuiteRegistry.CreateDefault();
        registry.Register(new FakeSuite("Ed25519Signature2020", proofTypes: ["Ed25519Signature2020"]));

        registry.GetByProofType(DataIntegrityProof.DataIntegrityProofType).Should().BeNull();
        registry.GetByProofType(null).Should().BeNull();
        registry.GetByProofType("").Should().BeNull();
        registry.GetByProofType("Ed25519Signature2018").Should().BeNull("no suite declares this type");
    }

    [Fact]
    public void GetByProofType_IsCaseSensitive_Ordinal()
    {
        var registry = new CryptosuiteRegistry();
        registry.Register(new FakeSuite("Ed25519Signature2020", proofTypes: ["Ed25519Signature2020"]));

        registry.GetByProofType("ED25519SIGNATURE2020").Should().BeNull("matching is ordinal, not case-insensitive");
    }

    [Fact]
    public void Register_IndexesSuiteUnderEachDeclaredNonDefaultType()
    {
        var registry = new CryptosuiteRegistry();
        var multi = new FakeSuite(
            "multi",
            proofTypes: [DataIntegrityProof.DataIntegrityProofType, "Ed25519Signature2020", "Ed25519Signature2018"]);

        registry.Register(multi);

        registry.GetByProofType("Ed25519Signature2020").Should().BeSameAs(multi);
        registry.GetByProofType("Ed25519Signature2018").Should().BeSameAs(multi);
        registry.GetByProofType(DataIntegrityProof.DataIntegrityProofType)
            .Should().BeNull("the default type is never indexed, even when a suite also declares it");
    }

    [Fact]
    public void Register_ReplacingLegacySuite_RemovesItsStaleTypeIndexEntries()
    {
        var registry = new CryptosuiteRegistry();
        registry.Register(new FakeSuite("legacy", proofTypes: ["Ed25519Signature2020"]));

        // Replace the same name with a default-type suite: the old type→suite mapping must go.
        var replacement = new FakeSuite("legacy");
        registry.Register(replacement);

        registry.GetByName("legacy").Should().BeSameAs(replacement);
        registry.GetByProofType("Ed25519Signature2020")
            .Should().BeNull("the replaced suite no longer claims the legacy type");
    }

    [Fact]
    public void Register_ReplacingLegacySuite_RepointsTypeIndexToTheNewSuite()
    {
        var registry = new CryptosuiteRegistry();
        registry.Register(new FakeSuite("legacy", proofTypes: ["Ed25519Signature2020"]));

        var replacement = new FakeSuite("legacy", proofTypes: ["Ed25519Signature2020"]);
        registry.Register(replacement);

        registry.GetByProofType("Ed25519Signature2020").Should().BeSameAs(replacement);
    }

    [Fact]
    public void Register_SameTypeUnderDifferentNames_IsLastRegistrationWins()
    {
        // Two differently named suites declaring the same legacy type: the type index is
        // last-registration-wins, mirroring the name index. (Benign — both claim the type
        // and each re-validates in VerifyProof.)
        var registry = new CryptosuiteRegistry();
        var first = new FakeSuite("suite-a", proofTypes: ["Ed25519Signature2020"]);
        var second = new FakeSuite("suite-b", proofTypes: ["Ed25519Signature2020"]);

        registry.Register(first);
        registry.Register(second);

        registry.GetByName("suite-a").Should().BeSameAs(first, "both names remain registered");
        registry.GetByName("suite-b").Should().BeSameAs(second);
        registry.GetByProofType("Ed25519Signature2020").Should().BeSameAs(second, "last registration wins");
    }

    [Fact]
    public void Register_ReplacingASuite_DoesNotStealAnotherNamesTypeEntry()
    {
        // suite-b currently owns the type. Replacing the unrelated suite-a (which also once
        // declared the type) must NOT remove suite-b's entry — the prune is value-matched.
        var registry = new CryptosuiteRegistry();
        registry.Register(new FakeSuite("suite-a", proofTypes: ["Ed25519Signature2020"]));
        var owner = new FakeSuite("suite-b", proofTypes: ["Ed25519Signature2020"]);
        registry.Register(owner);   // type -> suite-b

        // Replace suite-a with a default-type suite: it no longer claims the legacy type.
        registry.Register(new FakeSuite("suite-a"));

        registry.GetByProofType("Ed25519Signature2020")
            .Should().BeSameAs(owner, "the value-matched prune leaves the other name's entry intact");
    }

    [Fact]
    public void Register_SameInstanceTwice_IsIdempotent()
    {
        var registry = new CryptosuiteRegistry();
        var suite = new FakeSuite("legacy", proofTypes: ["Ed25519Signature2020"]);

        registry.Register(suite);
        registry.Register(suite);

        registry.GetByProofType("Ed25519Signature2020").Should().BeSameAs(suite);
    }

    private sealed class FakeSuite(string name, IReadOnlyCollection<string>? proofTypes = null) : ICryptosuite
    {
        public string Name => name;

        public IReadOnlyCollection<string> SupportedProofTypes
            => proofTypes ?? [DataIntegrityProof.DataIntegrityProofType];

        public Task<DataIntegrityProof> CreateProofAsync(
            JsonElement unsecuredDocument, DataIntegrityProof proofOptions, ISigner signer,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public ProofVerificationResult VerifyProof(
            JsonElement unsecuredDocument, DataIntegrityProof proof, DataProofsDotnet.PublicKeyMaterial publicKey)
            => throw new NotSupportedException();
    }
}
