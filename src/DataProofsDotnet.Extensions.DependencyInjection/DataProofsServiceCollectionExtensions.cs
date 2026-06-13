using DataProofsDotnet.DataIntegrity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace DataProofsDotnet.Extensions.DependencyInjection;

/// <summary>
/// Builder-style registration of the DataProofsDotnet proof layer (FR-22), mirroring the
/// <c>AddNetDid</c> idiom.
/// </summary>
/// <remarks>
/// This is a convenience composition layer. Everything it registers — the
/// <see cref="DataIntegrityProofPipeline"/>, the <see cref="CryptosuiteRegistry"/>, the
/// cryptosuites, and the JOSE/COSE supporting services — can equally be constructed by hand
/// without any container, exactly as the non-DI samples do (FR-22).
/// </remarks>
public static class DataProofsServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Data Integrity proof pipeline and a shared cryptosuite registry as
    /// thread-safe singletons (NFR-4), and runs <paramref name="configure"/> to opt into
    /// cryptosuites (<see cref="DataProofsBuilder.AddJcsSuites"/>,
    /// <see cref="DataProofsBuilder.AddRdfcSuites"/>, <see cref="DataProofsBuilder.AddBbs2023"/>),
    /// the enveloping families (<see cref="DataProofsBuilder.AddJose"/>,
    /// <see cref="DataProofsBuilder.AddCose"/>), and any caller-supplied verification-method
    /// resolvers (<see cref="DataProofsBuilder.AddVerificationMethodResolver(IVerificationMethodResolver)"/>).
    /// </summary>
    /// <param name="services">The service collection to add the registrations to.</param>
    /// <param name="configure">
    /// Callback that configures the builder. When <see langword="null"/>, no cryptosuites are
    /// registered and the resolved registry is empty — equivalent to
    /// <c>new CryptosuiteRegistry()</c>.
    /// </param>
    /// <returns>The same <see cref="IServiceCollection"/>, for chaining.</returns>
    /// <remarks>
    /// Idempotent and safe to call more than once: the pipeline and registry use
    /// <see cref="ServiceCollectionDescriptorExtensions.TryAddSingleton{TService}(IServiceCollection, TService)"/>,
    /// so a second call does not replace an already-registered singleton, and registering the
    /// same cryptosuite name twice overwrites harmlessly in the registry.
    /// </remarks>
    public static IServiceCollection AddDataProofs(
        this IServiceCollection services,
        Action<DataProofsBuilder>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var builder = new DataProofsBuilder(services);
        configure?.Invoke(builder);

        // The registry is fully assembled by the configuration callback; from here it is treated
        // as an immutable, shared singleton (NFR-4).
        var registry = builder.Registry;
        services.TryAddSingleton(registry);
        services.TryAddSingleton(sp => new DataIntegrityProofPipeline(
            sp.GetRequiredService<CryptosuiteRegistry>()));

        return services;
    }
}
