using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Jose;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Extensions.DependencyInjection.Tests;

/// <summary>
/// FR-22: the <c>AddDataProofs</c> builder composes the proof pipeline, the cryptosuite registry,
/// the per-package suite registrations, the enveloping families, and caller-supplied resolvers
/// into a dependency-injection container — and the composed pipeline actually produces and
/// verifies proofs (not merely resolves types).
/// </summary>
public class AddDataProofsTests
{
    [Fact]
    public void AddDataProofs_RegistersResolvablePipelineAndRegistry()
    {
        var services = new ServiceCollection();
        services.AddDataProofs(b => b.AddJcsSuites());
        var provider = services.BuildServiceProvider();

        provider.GetService<CryptosuiteRegistry>().Should().NotBeNull();
        provider.GetService<DataIntegrityProofPipeline>().Should().NotBeNull();
    }

    [Fact]
    public void AddDataProofs_WithNoConfigure_RegistersEmptyRegistry()
    {
        var services = new ServiceCollection();
        services.AddDataProofs();
        var provider = services.BuildServiceProvider();

        var registry = provider.GetRequiredService<CryptosuiteRegistry>();
        registry.RegisteredNames.Should().BeEmpty();
        provider.GetService<DataIntegrityProofPipeline>().Should().NotBeNull();
    }

    [Fact]
    public void Pipeline_SharesTheRegisteredRegistryInstance()
    {
        var services = new ServiceCollection();
        services.AddDataProofs(b => b.AddJcsSuites());
        var provider = services.BuildServiceProvider();

        var registry = provider.GetRequiredService<CryptosuiteRegistry>();
        var pipeline = provider.GetRequiredService<DataIntegrityProofPipeline>();

        // The pipeline must resolve over the very same registry singleton, so a suite added to
        // the registry at composition time is the one the pipeline dispatches to.
        pipeline.Suites.Should().BeSameAs(registry);
    }

    [Fact]
    public void AddJcsSuites_RegistersTheJcsSuiteNames()
    {
        var services = new ServiceCollection();
        services.AddDataProofs(b => b.AddJcsSuites());
        var provider = services.BuildServiceProvider();

        var registry = provider.GetRequiredService<CryptosuiteRegistry>();
        registry.RegisteredNames.Should().Contain(
        [
            EddsaJcs2022Cryptosuite.CryptosuiteName,
            EcdsaJcs2019Cryptosuite.CryptosuiteName,
        ]);
    }

    [Fact]
    public void AddRdfcSuitesAndBbs2023_RegisterTheirSuiteNames()
    {
        var services = new ServiceCollection();
        services.AddDataProofs(b => b.AddJcsSuites().AddRdfcSuites().AddBbs2023());
        var provider = services.BuildServiceProvider();

        var registry = provider.GetRequiredService<CryptosuiteRegistry>();
        registry.RegisteredNames.Should().Contain(
        [
            EddsaJcs2022Cryptosuite.CryptosuiteName,
            EcdsaJcs2019Cryptosuite.CryptosuiteName,
            "eddsa-rdfc-2022",
            "ecdsa-rdfc-2019",
            "bbs-2023",
        ]);
    }

    [Fact]
    public void AddVerificationMethodResolver_RegistersAResolvableResolver()
    {
        var resolver = new StaticVerificationMethodResolver([]);

        var services = new ServiceCollection();
        services.AddDataProofs(b => b
            .AddJcsSuites()
            .AddVerificationMethodResolver(resolver));
        var provider = services.BuildServiceProvider();

        provider.GetService<IVerificationMethodResolver>().Should().BeSameAs(resolver);
    }

    [Fact]
    public void AddJose_RegistersTheJoseCryptoProvider()
    {
        var services = new ServiceCollection();
        services.AddDataProofs(b => b.AddJose());
        var provider = services.BuildServiceProvider();

        provider.GetService<IJoseCryptoProvider>().Should().NotBeNull();
        provider.GetService<JoseCryptoProvider>().Should().NotBeNull();
        provider.GetService<ICryptoProvider>().Should().NotBeNull();
        // The interface and concrete registrations resolve the same singleton instance.
        provider.GetRequiredService<IJoseCryptoProvider>()
            .Should().BeSameAs(provider.GetRequiredService<JoseCryptoProvider>());
    }

    [Fact]
    public void AddCose_RegistersTheSharedCryptoProvider()
    {
        var services = new ServiceCollection();
        services.AddDataProofs(b => b.AddCose());
        var provider = services.BuildServiceProvider();

        provider.GetService<ICryptoProvider>().Should().NotBeNull();
    }

    [Fact]
    public void CoreServices_AreSingletons()
    {
        var services = new ServiceCollection();
        services.AddDataProofs(b => b.AddJcsSuites().AddJose());
        var provider = services.BuildServiceProvider();

        provider.GetRequiredService<CryptosuiteRegistry>()
            .Should().BeSameAs(provider.GetRequiredService<CryptosuiteRegistry>());
        provider.GetRequiredService<DataIntegrityProofPipeline>()
            .Should().BeSameAs(provider.GetRequiredService<DataIntegrityProofPipeline>());
        provider.GetRequiredService<IJoseCryptoProvider>()
            .Should().BeSameAs(provider.GetRequiredService<IJoseCryptoProvider>());
        provider.GetRequiredService<ICryptoProvider>()
            .Should().BeSameAs(provider.GetRequiredService<ICryptoProvider>());
    }

    [Fact]
    public void AddDataProofs_IsIdempotent_DoesNotReplaceTheRegistry()
    {
        var services = new ServiceCollection();
        services.AddDataProofs(b => b.AddJcsSuites());
        var firstRegistryDescriptorCount = services.Count(d => d.ServiceType == typeof(CryptosuiteRegistry));

        // Second call: the configure callback builds a fresh (empty) registry, but TryAddSingleton
        // must keep the already-registered one, leaving exactly one registry descriptor.
        services.AddDataProofs(b => b.AddRdfcSuites());

        services.Count(d => d.ServiceType == typeof(CryptosuiteRegistry))
            .Should().Be(firstRegistryDescriptorCount).And.Be(1);

        var provider = services.BuildServiceProvider();
        // The surviving registry is the first one (JCS suites), not the second (RDFC suites).
        var registry = provider.GetRequiredService<CryptosuiteRegistry>();
        registry.RegisteredNames.Should().Contain(EddsaJcs2022Cryptosuite.CryptosuiteName);
        registry.RegisteredNames.Should().NotContain("eddsa-rdfc-2022");
    }

    [Fact]
    public async Task EndToEnd_ResolvedPipeline_CreatesAndVerifiesAJcsProof()
    {
        // Smoke test: compose the pipeline through DI, then prove the composition actually works
        // by producing and verifying a real eddsa-jcs-2022 proof with a key-store-backed signer.
        var services = new ServiceCollection();
        services.AddDataProofs(b => b.AddJcsSuites());
        var provider = services.BuildServiceProvider();

        var pipeline = provider.GetRequiredService<DataIntegrityProofPipeline>();

        var keyGen = new DefaultKeyGenerator();
        var crypto = new DefaultCryptoProvider();
        var store = new InMemoryKeyStore(keyGen, crypto);
        var seed = Enumerable.Repeat((byte)0x42, 32).ToArray();
        var info = await store.ImportAsync("signing-key", keyGen.FromPrivateKey(KeyType.Ed25519, seed));
        var signer = await store.CreateSignerAsync("signing-key");

        var unsecured = JsonSerializer.Deserialize<JsonElement>(
            """
            {
              "@context": ["https://www.w3.org/ns/credentials/v2"],
              "type": ["VerifiableCredential"],
              "issuer": "did:example:issuer",
              "credentialSubject": { "id": "did:example:subject", "name": "Alice" }
            }
            """);

        var secured = await pipeline.AddProofAsync(
            unsecured,
            new DataIntegrityProof
            {
                Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
                Created = "2026-01-02T00:00:00Z",
                VerificationMethod = "did:example:issuer#key-1",
                ProofPurpose = ProofPurposes.AssertionMethod,
            },
            signer);

        secured.TryGetProperty("proof", out _).Should().BeTrue("the pipeline must embed a proof block");

        var result = pipeline.Verify(secured, PublicKeyMaterial.FromRaw(KeyType.Ed25519, info.PublicKey));
        result.Verified.Should().BeTrue();
        result.Problems.Should().BeEmpty();

        // Negative control: tampering the document fails verification (a result, not an exception).
        var tampered = JsonSerializer.Deserialize<JsonElement>(
            JsonSerializer.Serialize(secured).Replace("Alice", "Mallory"));
        pipeline.Verify(tampered, PublicKeyMaterial.FromRaw(KeyType.Ed25519, info.PublicKey))
            .Verified.Should().BeFalse();
    }
}
