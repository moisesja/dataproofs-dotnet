using DataProofsDotnet;

namespace DataProofsDotnet.Rdfc;

/// <summary>
/// Thrown when JSON-LD processing or RDF Dataset Canonicalization (RDFC-1.0) fails — for
/// example malformed JSON-LD/N-Quads input, an unresolvable or unauthorized context (the
/// offline loader fails closed, FR-10), or a canonicalization the underlying processor
/// rejects (RDFC-1.0 negative/poison cases, AC-2).
/// </summary>
/// <remarks>
/// This is the documented wrapper exception of the <c>Rdfc</c> canonicalizer interface
/// (FR-9): no <c>dotNetRDF</c> or <c>Newtonsoft</c> exception type ever surfaces to a
/// caller. Messages never carry key material or secrets (FR-23).
/// </remarks>
public sealed class RdfCanonicalizationException : DataProofsException
{
    /// <summary>Creates an exception with a message.</summary>
    public RdfCanonicalizationException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and an inner cause.</summary>
    public RdfCanonicalizationException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }
}
