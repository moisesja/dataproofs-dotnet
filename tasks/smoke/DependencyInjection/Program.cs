// ============================================================
// AC-10 smoke — DataProofsDotnet.Extensions.DependencyInjection
// ============================================================
// AddDataProofs resolution: compose the pipeline + cryptosuite registry through the DI builder,
// then resolve them from the built provider and confirm the registered suites are present.
// Prints OK and exits 0 on success.

using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

Console.WriteLine("=== DataProofsDotnet.Extensions.DependencyInjection smoke — AddDataProofs resolution ===");

// 1. Compose: register the pipeline + registry, add the JCS suites, and the JOSE services.
var services = new ServiceCollection();
services.AddDataProofs(builder =>
{
    builder.AddJcsSuites()
           .AddJose();
});

using var provider = services.BuildServiceProvider();

// 2. Resolve the composed pipeline and registry.
var pipeline = provider.GetRequiredService<DataIntegrityProofPipeline>();
var registry = provider.GetRequiredService<CryptosuiteRegistry>();
Check(pipeline is not null, "DataIntegrityProofPipeline resolves from the container");
Check(ReferenceEquals(pipeline!.Suites, registry), "pipeline shares the registered cryptosuite registry");
Console.WriteLine("  resolved DataIntegrityProofPipeline + CryptosuiteRegistry");

// 3. Confirm the JCS suites registered through the builder are present.
Check(registry.GetByName(EddsaJcs2022Cryptosuite.CryptosuiteName) is not null, "eddsa-jcs-2022 suite is registered");
Check(registry.GetByName(EcdsaJcs2019Cryptosuite.CryptosuiteName) is not null, "ecdsa-jcs-2019 suite is registered");
Console.WriteLine($"  registry exposes {registry.RegisteredNames.Count} cryptosuite(s): {string.Join(", ", registry.RegisteredNames)}");

Console.WriteLine("OK — DataProofsDotnet.Extensions.DependencyInjection smoke passed.");
return 0;

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.Error.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}
