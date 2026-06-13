using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.Core.Tests.TestSupport;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Core.Tests;

/// <summary>
/// AC-8 groundwork (no-key-surrender): producing a Data Integrity proof through a
/// key-store-backed signer touches ONLY the signing-only members of
/// <see cref="IKeyStore"/> (<c>SignAsync</c>/<c>CreateSignerAsync</c>/<c>GetInfoAsync</c>),
/// and no public signing entry point accepts raw private-key bytes.
/// </summary>
public class KeyStoreSigningTests
{
    private static readonly DataIntegrityProofPipeline Pipeline = new();

    private static JsonElement UnsignedDocument()
        => Fx.Json("constructed", "controller", "unsigned-credential.json");

    [Theory]
    [InlineData(EddsaJcs2022Cryptosuite.CryptosuiteName, KeyType.Ed25519)]
    [InlineData(EcdsaJcs2019Cryptosuite.CryptosuiteName, KeyType.P256)]
    [InlineData(EcdsaJcs2019Cryptosuite.CryptosuiteName, KeyType.P384)]
    public async Task ProducingAJcsProof_TouchesOnlySigningMembersOfTheKeyStore(string cryptosuite, KeyType keyType)
    {
        var store = new RecordingKeyStore(new InMemoryKeyStore(Fx.KeyGen, Fx.Crypto));

        // Setup phase: import only.
        var info = await store.ImportAsync("signing-key", Fx.SeedKey(0x21, keyType));
        store.ClearCalls();

        // Production phase: key-store-backed signer -> proof -> verify.
        var signer = await store.CreateSignerAsync("signing-key");
        var secured = await Pipeline.AddProofAsync(
            UnsignedDocument(),
            new DataIntegrityProof
            {
                Cryptosuite = cryptosuite,
                Created = "2026-01-02T00:00:00Z",
                VerificationMethod = "did:example:store#signing-key",
                ProofPurpose = ProofPurposes.AssertionMethod,
            },
            signer);

        Pipeline.Verify(secured, PublicKeyMaterial.FromRaw(keyType, info.PublicKey)).Verified.Should().BeTrue();

        store.Calls.Should().NotBeEmpty();
        store.Calls.Should().OnlyContain(
            call => call == nameof(IKeyStore.SignAsync)
                || call == nameof(IKeyStore.CreateSignerAsync)
                || call == nameof(IKeyStore.GetInfoAsync));
        store.Calls.Should().Contain(nameof(IKeyStore.SignAsync));
    }

    [Fact]
    public void NoPublicSigningEntryPoint_AcceptsRawPrivateKeyBytes()
    {
        // Every public method that produces a signature must take a NetCrypto ISigner;
        // none may take key bytes (byte[], spans, or memory) anywhere in its signature.
        var assembly = typeof(DataIntegrityProofPipeline).Assembly;
        var signingMethods = assembly.GetExportedTypes()
            .SelectMany(t => t.GetMethods(System.Reflection.BindingFlags.Public
                | System.Reflection.BindingFlags.Instance
                | System.Reflection.BindingFlags.Static
                | System.Reflection.BindingFlags.DeclaredOnly))
            .Where(m => m.Name is "AddProofAsync" or "CreateProofAsync")
            .ToList();

        signingMethods.Should().NotBeEmpty();
        foreach (var method in signingMethods)
        {
            var parameterTypes = method.GetParameters().Select(p => p.ParameterType).ToList();
            parameterTypes.Should().Contain(typeof(ISigner),
                $"{method.DeclaringType!.Name}.{method.Name} must sign through NetCrypto ISigner");
            parameterTypes.Should().NotContain(
                t => t == typeof(byte[]) || t == typeof(ReadOnlyMemory<byte>) || t == typeof(Memory<byte>),
                $"{method.DeclaringType!.Name}.{method.Name} must never accept raw key bytes");
        }
    }
}
