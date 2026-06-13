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

    // NOTE: AddBbs2023(...) and the bbs-2023 wiring of CreateWithRdfcSuites are added by the
    // FR-12 bbs-2023 work; the RDFC suites (FR-11) land first on a proven pipeline (PRD §10).

    /// <summary>
    /// Creates a registry pre-populated with everything <c>Core</c> ships (the JCS suites)
    /// plus the RDFC suites — the deterministic-signature v1 Data Integrity suite set.
    /// (<c>bbs-2023</c> is added by <c>AddBbs2023</c> once the FR-12 suite is registered.)
    /// </summary>
    public static CryptosuiteRegistry CreateWithRdfcSuites(IRdfCanonicalizer? canonicalizer = null)
    {
        var registry = CryptosuiteRegistry.CreateDefault();
        registry.AddRdfcSuites(canonicalizer);
        return registry;
    }
}
