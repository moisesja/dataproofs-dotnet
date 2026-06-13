namespace DataProofsDotnet.Rdfc;

/// <summary>
/// The hash algorithm RDF Dataset Canonicalization (RDFC-1.0) uses internally to label
/// blank nodes. RDFC-1.0 defaults to SHA-256; the <c>ecdsa-rdfc-2019</c> P-384 path and a
/// small number of W3C conformance vectors select SHA-384.
/// </summary>
public enum RdfCanonicalizationHashAlgorithm
{
    /// <summary>SHA-256 — the RDFC-1.0 default.</summary>
    Sha256 = 0,

    /// <summary>SHA-384 — used by the P-384 ECDSA path and the SHA-384 conformance vectors.</summary>
    Sha384 = 1,
}
