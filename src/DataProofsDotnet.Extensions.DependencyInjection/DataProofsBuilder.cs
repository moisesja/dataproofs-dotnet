using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Rdfc;
using DataProofsDotnet.Rdfc.DataIntegrity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NetCrypto;

namespace DataProofsDotnet.Extensions.DependencyInjection;

/// <summary>
/// Builder for composing the DataProofsDotnet proof layer in a dependency-injection container
/// (FR-22). Obtained from
/// <see cref="DataProofsServiceCollectionExtensions.AddDataProofs(IServiceCollection, System.Action{DataProofsBuilder})"/>;
/// its <c>Add…</c> methods register cryptosuites onto a single shared
/// <see cref="CryptosuiteRegistry"/> and the per-family envelope services (JOSE, COSE).
/// </summary>
/// <remarks>
/// <para>
/// This builder is a <em>convenience layer only</em>: it composes the very same immutable
/// pipeline, registry, and suite types that every non-DI sample constructs by hand, so manual
/// construction (e.g. <c>new DataIntegrityProofPipeline(CryptosuiteRegistry.CreateDefault())</c>)
/// remains fully supported and is never hidden behind the container.
/// </para>
/// <para>
/// The assembled <see cref="Registry"/> is mutable while the configuration callback runs and
/// becomes an immutable, thread-safe singleton once
/// <see cref="DataProofsServiceCollectionExtensions.AddDataProofs(IServiceCollection, System.Action{DataProofsBuilder})"/>
/// returns (NFR-4).
/// </para>
/// </remarks>
public sealed class DataProofsBuilder
{
    /// <summary>The service collection the registrations are written into.</summary>
    public IServiceCollection Services { get; }

    /// <summary>
    /// The shared cryptosuite registry the suite-registration methods populate. It is registered
    /// as a singleton by the parent <c>AddDataProofs</c> call and is treated as immutable after
    /// that point.
    /// </summary>
    public CryptosuiteRegistry Registry { get; }

    internal DataProofsBuilder(IServiceCollection services)
    {
        Services = services;
        Registry = new CryptosuiteRegistry();
    }

    /// <summary>
    /// Registers the JCS cryptosuites owned by <c>Core</c> — <c>eddsa-jcs-2022</c> and
    /// <c>ecdsa-jcs-2019</c> (FR-5) — onto the shared registry. Registering the same suite name
    /// twice is harmless: the underlying registry overwrites by name (idempotent).
    /// </summary>
    /// <returns>The same builder, for chaining.</returns>
    public DataProofsBuilder AddJcsSuites()
    {
        Registry.Register(new EddsaJcs2022Cryptosuite());
        Registry.Register(new EcdsaJcs2019Cryptosuite());
        return this;
    }

    /// <summary>
    /// Registers the RDFC cryptosuites owned by <c>Rdfc</c> — <c>eddsa-rdfc-2022</c> and
    /// <c>ecdsa-rdfc-2019</c> (FR-11) — onto the shared registry, sharing one canonicalizer
    /// (offline-default loader when <paramref name="canonicalizer"/> is omitted).
    /// </summary>
    /// <param name="canonicalizer">
    /// The RDF canonicalizer the suites share; the offline-default
    /// <see cref="RdfcDocumentCanonicalizer"/> is used when <see langword="null"/>.
    /// </param>
    /// <returns>The same builder, for chaining.</returns>
    public DataProofsBuilder AddRdfcSuites(IRdfCanonicalizer? canonicalizer = null)
    {
        Registry.AddRdfcSuites(canonicalizer);
        return this;
    }

    /// <summary>
    /// Registers the <c>bbs-2023</c> selective-disclosure cryptosuite owned by <c>Rdfc</c>
    /// (FR-12) onto the shared registry, over the offline-default RDFC canonicalizer when
    /// <paramref name="canonicalizer"/> is omitted.
    /// </summary>
    /// <param name="canonicalizer">
    /// The RDF canonicalizer the suite uses; the offline-default
    /// <see cref="RdfcDocumentCanonicalizer"/> is used when <see langword="null"/>.
    /// </param>
    /// <remarks>
    /// Registration always succeeds, even when the BBS native binaries are absent on the host:
    /// use throws NetCrypto's documented unavailable exception only when actually exercised.
    /// </remarks>
    /// <returns>The same builder, for chaining.</returns>
    public DataProofsBuilder AddBbs2023(IRdfCanonicalizer? canonicalizer = null)
    {
        Registry.AddBbs2023(canonicalizer);
        return this;
    }

    /// <summary>
    /// Registers the JOSE family services (FR-13–FR-18). A singleton
    /// <see cref="IJoseCryptoProvider"/> (concrete <see cref="JoseCryptoProvider"/>) is added over
    /// the container's <see cref="ICryptoProvider"/>; the JWS/JWE/JWT/SD-JWT/VC-JOSE entry points
    /// are static and consume this provider.
    /// </summary>
    /// <returns>The same builder, for chaining.</returns>
    public DataProofsBuilder AddJose()
    {
        EnsureCryptoProvider();
        Services.TryAddSingleton<JoseCryptoProvider>(sp =>
            new JoseCryptoProvider(sp.GetRequiredService<ICryptoProvider>()));
        Services.TryAddSingleton<IJoseCryptoProvider>(sp => sp.GetRequiredService<JoseCryptoProvider>());
        return this;
    }

    /// <summary>
    /// Registers the COSE family supporting services (FR-19). The <c>COSE_Sign1</c>/CWT/VC-COSE
    /// entry points are static and sign through a NetCrypto <see cref="ISigner"/>; this registers
    /// the shared <see cref="ICryptoProvider"/> the verification helpers use.
    /// </summary>
    /// <returns>The same builder, for chaining.</returns>
    public DataProofsBuilder AddCose()
    {
        EnsureCryptoProvider();
        return this;
    }

    /// <summary>
    /// Registers a caller-supplied verification-method resolver (FR-7) as a singleton
    /// <see cref="IVerificationMethodResolver"/>. <c>Core</c> ships no DID-aware resolver, so the
    /// resolver-driven verification path requires the consumer to register one here.
    /// </summary>
    /// <param name="resolver">The resolver instance to register.</param>
    /// <returns>The same builder, for chaining.</returns>
    public DataProofsBuilder AddVerificationMethodResolver(IVerificationMethodResolver resolver)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        Services.TryAddSingleton(resolver);
        return this;
    }

    private void EnsureCryptoProvider()
        => Services.TryAddSingleton<ICryptoProvider, DefaultCryptoProvider>();
}
