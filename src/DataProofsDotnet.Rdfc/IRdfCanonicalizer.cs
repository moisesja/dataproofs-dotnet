using System.Text.Json;

namespace DataProofsDotnet.Rdfc;

/// <summary>
/// This library's own RDF Dataset Canonicalization (RDFC-1.0) abstraction (FR-9): JSON-LD
/// 1.1 expansion and RDFC-1.0 canonicalization wrapped so no <c>dotNetRDF</c> or
/// <c>Newtonsoft</c> type ever appears in a public signature (AC-7). Conformance is the
/// unit under test in AC-2 — the wrapper, not the underlying processor.
/// </summary>
/// <remarks>Implementations must be immutable and thread-safe after construction (NFR-4).</remarks>
public interface IRdfCanonicalizer
{
    /// <summary>
    /// Expands a JSON-LD document to an RDF dataset and canonicalizes it under RDFC-1.0,
    /// returning the canonical N-Quads as UTF-8 bytes (the suites hash these directly).
    /// </summary>
    /// <param name="document">The JSON-LD document to canonicalize (a JSON object).</param>
    /// <param name="hashAlgorithm">The RDFC-1.0 blank-node hashing algorithm (default SHA-256).</param>
    /// <returns>The canonical N-Quads as UTF-8 bytes.</returns>
    /// <exception cref="RdfCanonicalizationException">
    /// JSON-LD processing or canonicalization failed, or a referenced context could not be
    /// loaded (the offline loader fails closed).
    /// </exception>
    byte[] CanonicalizeJsonLd(JsonElement document, RdfCanonicalizationHashAlgorithm hashAlgorithm = RdfCanonicalizationHashAlgorithm.Sha256);

    /// <summary>
    /// Canonicalizes an RDF dataset supplied as N-Quads under RDFC-1.0, returning the
    /// canonical N-Quads string. (The conformance harness's evaluation direction, AC-2.)
    /// </summary>
    /// <param name="nQuads">The input dataset as N-Quads text.</param>
    /// <param name="hashAlgorithm">The RDFC-1.0 blank-node hashing algorithm (default SHA-256).</param>
    /// <returns>The canonical N-Quads string.</returns>
    /// <exception cref="RdfCanonicalizationException">The input is malformed or canonicalization was rejected.</exception>
    string CanonicalizeNQuads(string nQuads, RdfCanonicalizationHashAlgorithm hashAlgorithm = RdfCanonicalizationHashAlgorithm.Sha256);

    /// <summary>
    /// Canonicalizes an N-Quads dataset and returns the issued-identifier map: original
    /// blank-node label → canonical (<c>c14n*</c>) label. (The conformance harness's map
    /// direction, AC-2.)
    /// </summary>
    /// <param name="nQuads">The input dataset as N-Quads text.</param>
    /// <param name="hashAlgorithm">The RDFC-1.0 blank-node hashing algorithm (default SHA-256).</param>
    /// <returns>The issued-identifier map, keyed by original blank-node identifier (without the <c>_:</c> prefix).</returns>
    /// <exception cref="RdfCanonicalizationException">The input is malformed or canonicalization was rejected.</exception>
    IReadOnlyDictionary<string, string> CanonicalizeNQuadsToMap(string nQuads, RdfCanonicalizationHashAlgorithm hashAlgorithm = RdfCanonicalizationHashAlgorithm.Sha256);
}
