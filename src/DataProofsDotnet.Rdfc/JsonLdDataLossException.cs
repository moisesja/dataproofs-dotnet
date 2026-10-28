namespace DataProofsDotnet.Rdfc;

/// <summary>
/// Thrown when a JSON-LD input cannot be canonicalized without losing data: JSON-LD processing
/// would drop part of it, or the canonical N-Quads would spell one of its IRIs differently
/// (issue #36). Whatever is dropped is not signed, so a proof over it could not secure it.
/// </summary>
/// <remarks>
/// <para>
/// VC Data Integrity 1.0 §2.4.3 requires an error, which should be <c>DATA_LOSS_DETECTION_ERROR</c>,
/// when a JSON-LD processor drops data. The RDFC suites report this exception as that code when
/// verifying, and wrap it in a <see cref="ProofGenerationException"/> when creating a proof.
/// </para>
/// <para>
/// Typical causes are a term the document's <c>@context</c> does not define (VCDM 2.0 §5.2 asks
/// such documents to list <c>https://www.w3.org/ns/credentials/undefined-terms/v2</c> last), an IRI
/// that is not a well-formed absolute IRI, and an IRI the canonical form would normalize, such as
/// one with a <c>..</c> segment or a percent-encoded unreserved character. The message names the
/// cause but never quotes the input (FR-23).
/// </para>
/// </remarks>
public sealed class JsonLdDataLossException : RdfCanonicalizationException
{
    /// <summary>Creates an exception with a message.</summary>
    public JsonLdDataLossException(string message)
        : base(message)
    {
    }
}
