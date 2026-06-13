using DataProofsDotnet.DataIntegrity;

namespace DataProofsDotnet.Rdfc.DataIntegrity;

/// <summary>
/// Registration entry points for the cryptosuites this package owns (FR-4/FR-11/FR-12):
/// <c>eddsa-rdfc-2022</c>, <c>ecdsa-rdfc-2019</c>, and <c>bbs-2023</c>. (The JCS suites are
/// registered by <c>Core</c>; these register here.)
/// </summary>
public static class RdfcCryptosuiteRegistration
{
    /// <summary>
    /// Registers the RDFC cryptosuites (<c>eddsa-rdfc-2022</c>, <c>ecdsa-rdfc-2019</c>) into
    /// <paramref name="registry"/>, sharing one RDFC canonicalizer (offline-default loader
    /// when <paramref name="canonicalizer"/> is omitted).
    /// </summary>
    /// <returns>The same registry, for chaining.</returns>
    public static CryptosuiteRegistry AddRdfcSuites(this CryptosuiteRegistry registry, IRdfCanonicalizer? canonicalizer = null)
    {
        ArgumentNullException.ThrowIfNull(registry);
        canonicalizer ??= new RdfcDocumentCanonicalizer();
        registry.Register(new EddsaRdfc2022Cryptosuite(canonicalizer));
        registry.Register(new EcdsaRdfc2019Cryptosuite(canonicalizer));
        return registry;
    }

    /// <summary>
    /// Registers the <c>bbs-2023</c> selective-disclosure cryptosuite (FR-12) into
    /// <paramref name="registry"/>, over the offline-default RDFC canonicalizer when
    /// <paramref name="canonicalizer"/> is omitted.
    /// </summary>
    /// <remarks>
    /// Registration always succeeds, even when the BBS native binaries are absent on the host
    /// (AC-6): the capability is probed lazily, and the <c>bbs-2023</c> lifecycle methods throw
    /// NetCrypto's documented <c>BbsUnavailableException</c> only when actually used without
    /// native support.
    /// </remarks>
    /// <returns>The same registry, for chaining.</returns>
    public static CryptosuiteRegistry AddBbs2023(this CryptosuiteRegistry registry, IRdfCanonicalizer? canonicalizer = null)
    {
        ArgumentNullException.ThrowIfNull(registry);
        canonicalizer ??= new RdfcDocumentCanonicalizer();
        registry.Register(new Bbs2023Cryptosuite(canonicalizer));
        return registry;
    }

    /// <summary>
    /// Creates a registry pre-populated with everything <c>Core</c> ships (the JCS suites)
    /// plus the RDFC suites (<c>eddsa-rdfc-2022</c>, <c>ecdsa-rdfc-2019</c>) and the
    /// selective-disclosure <c>bbs-2023</c> suite — the full v1 Data Integrity suite set.
    /// </summary>
    public static CryptosuiteRegistry CreateWithRdfcSuites(IRdfCanonicalizer? canonicalizer = null)
    {
        var registry = CryptosuiteRegistry.CreateDefault();
        registry.AddRdfcSuites(canonicalizer);
        registry.AddBbs2023(canonicalizer);
        return registry;
    }
}
