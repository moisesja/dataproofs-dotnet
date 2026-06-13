using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Extensions.DependencyInjection;
using DataProofsDotnet.Jose;
using Microsoft.Extensions.DependencyInjection;
using NetCrypto;

// ============================================================
// DataProofsDotnet Samples — Dependency Injection (AddDataProofs)
// ============================================================
// FR-22: the AddDataProofs builder composes the proof pipeline, the cryptosuite registry, the
// per-package suite registrations, and the enveloping families into a service container — the
// AddNetDid idiom. This is the ONLY sample that uses the DI package; every other sample
// constructs the very same objects by hand, because the DI package COMPOSES, it does not hide.
//
// builder methods:
//   AddJcsSuites()  — eddsa-jcs-2022 + ecdsa-jcs-2019 (Core)
//   AddRdfcSuites() — eddsa-rdfc-2022 + ecdsa-rdfc-2019 (Rdfc), optional custom canonicalizer
//   AddBbs2023()    — bbs-2023 (Rdfc), optional custom canonicalizer
//   AddJose()       — the JoseCryptoProvider
//   AddCose()       — the shared NetCrypto ICryptoProvider
//   AddVerificationMethodResolver(resolver) — a caller-supplied IVerificationMethodResolver

Console.WriteLine("=== AddDataProofs — composing the library through DI ===");

// A caller-supplied resolver to register alongside the suites.
KeyPair issuerKey = new DefaultKeyGenerator().Generate(KeyType.Ed25519);
string vm = $"did:key:{issuerKey.MultibasePublicKey}#{issuerKey.MultibasePublicKey}";
var resolver = new StaticVerificationMethodResolver(
[
    new ResolvedVerificationMethod
    {
        Id = vm,
        Controller = $"did:key:{issuerKey.MultibasePublicKey}",
        PublicKey = PublicKeyMaterial.FromMultikey(issuerKey.MultibasePublicKey),
        Relationships = new HashSet<string>(StringComparer.Ordinal) { ProofPurposes.AssertionMethod },
        ControllerControlsMethod = true,
    },
]);

// Register everything in one fluent call. The builder also exposes Services + Registry so
// callers can add their own descriptors or inspect what was registered.
// AddDataProofs is the DataProofsServiceCollectionExtensions entry point; its callback receives a
// DataProofsBuilder. Both type names are spelled out here so the composition surface is explicit.
var services = new ServiceCollection();
services.AddDataProofs((DataProofsBuilder builder) =>
{
    Console.WriteLine($"  builder.Services is the same IServiceCollection: {ReferenceEquals(builder.Services, services)}");
    builder
        .AddJcsSuites()
        .AddRdfcSuites()
        .AddBbs2023()
        .AddJose()
        .AddCose()
        .AddVerificationMethodResolver(resolver);

    // The builder's Registry is observable mid-composition.
    Console.WriteLine($"  registry after registrations: {string.Join(", ", builder.Registry.RegisteredNames)}");
    Check(builder.Registry.RegisteredNames.Contains(EddsaJcs2022Cryptosuite.CryptosuiteName), "JCS suites registered on the builder registry");
});

ServiceProvider provider = services.BuildServiceProvider();

// Everything resolves as singletons.
var registry = provider.GetRequiredService<CryptosuiteRegistry>();
var pipeline = provider.GetRequiredService<DataIntegrityProofPipeline>();
var joseProvider = provider.GetRequiredService<IJoseCryptoProvider>();
var cryptoProvider = provider.GetRequiredService<ICryptoProvider>();
var resolvedResolver = provider.GetRequiredService<IVerificationMethodResolver>();

Console.WriteLine($"  resolved singletons: {registry.GetType().Name}, {pipeline.GetType().Name}, {joseProvider.GetType().Name}, {cryptoProvider.GetType().Name}");
Check(pipeline.Suites.RegisteredNames.Contains("eddsa-rdfc-2022"), "RDFC suites are registered");
Check(pipeline.Suites.RegisteredNames.Contains("bbs-2023"), "bbs-2023 is registered");
Check(ReferenceEquals(pipeline.Suites, registry), "the pipeline dispatches over the same registry singleton");
Check(ReferenceEquals(resolvedResolver, resolver), "the caller-supplied resolver resolves back");
Check(ReferenceEquals(provider.GetRequiredService<DataIntegrityProofPipeline>(), pipeline), "the pipeline is a singleton");
Console.WriteLine();

// ----------------------------------------------------------- Use the composed pipeline end to end
Console.WriteLine("--- the DI-composed pipeline actually signs and verifies ---");

// A store-backed signer (the same AC-8 posture as the hand-built samples).
var keyGen = new DefaultKeyGenerator();
var store = new InMemoryKeyStore(keyGen, cryptoProvider);
StoredKeyInfo info = await store.ImportAsync("issuer", keyGen.FromPrivateKey(KeyType.Ed25519, issuerKey.PrivateKey));
ISigner signer = await store.CreateSignerAsync("issuer");

JsonElement unsigned = JsonSerializer.Deserialize<JsonElement>(
    """
    {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      "type": ["VerifiableCredential"],
      "issuer": "did:example:issuer",
      "credentialSubject": { "id": "did:example:subject", "name": "Alice Example" }
    }
    """);

JsonElement secured = await pipeline.AddProofAsync(
    unsigned,
    new DataIntegrityProof
    {
        Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
        Created = "2026-01-02T00:00:00Z",
        VerificationMethod = vm,
        ProofPurpose = ProofPurposes.AssertionMethod,
    },
    signer);

// Verify via the DI-resolved resolver (full algorithm) and via raw key.
DocumentVerificationResult viaResolver = await pipeline.VerifyAsync(
    secured, resolvedResolver, new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });
DocumentVerificationResult viaRawKey = pipeline.Verify(secured, PublicKeyMaterial.FromRaw(KeyType.Ed25519, info.PublicKey));
Console.WriteLine($"  resolver-path verified: {viaResolver.Verified}; raw-key-path verified: {viaRawKey.Verified}");
Check(viaResolver.Verified, "the DI-composed pipeline verifies on the resolver path");
Check(viaRawKey.Verified, "the DI-composed pipeline verifies on the raw-key path");

// ----------------------------------------------------------- AddDataProofs with no configure
Console.WriteLine();
Console.WriteLine("--- AddDataProofs() with no configuration registers an empty registry + pipeline ---");
var bare = new ServiceCollection();
bare.AddDataProofs();
var bareProvider = bare.BuildServiceProvider();
Check(bareProvider.GetRequiredService<CryptosuiteRegistry>().RegisteredNames.Count == 0, "no-configure registry is empty");
Check(bareProvider.GetService<DataIntegrityProofPipeline>() is not null, "the pipeline still resolves with no suites");
Console.WriteLine($"  empty registry size: {bareProvider.GetRequiredService<CryptosuiteRegistry>().RegisteredNames.Count}");

Console.WriteLine();
Console.WriteLine("Done! Dependency-injection example completed successfully.");
return 0;

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
