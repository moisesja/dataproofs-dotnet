namespace DataProofsDotnet.Rdfc;

/// <summary>
/// A pluggable JSON-LD context loader (FR-10). The RDFC canonicalizer consults a loader
/// for every <c>@context</c> URL encountered during JSON-LD expansion.
/// </summary>
/// <remarks>
/// <para>
/// The default policy is <b>offline-only</b> (<see cref="OfflineDocumentLoader"/>): the
/// loader serves version-pinned, provenance-tracked embedded copies of the core W3C
/// contexts and <b>fails closed</b> — throwing — on any context outside the bundled set.
/// A security operation's correctness never depends on a remote host being reachable, and
/// verification performs no ambient network I/O.
/// </para>
/// <para>
/// <see cref="CachingNetworkDocumentLoader"/> ships for callers who explicitly opt in to
/// network retrieval; it is <b>never</b> the default and must be constructed deliberately.
/// </para>
/// <para>Implementations must be thread-safe (NFR-4).</para>
/// </remarks>
public interface IDocumentLoader
{
    /// <summary>
    /// Loads the JSON-LD context document at <paramref name="url"/>.
    /// </summary>
    /// <param name="url">The context URL to resolve.</param>
    /// <returns>The loaded context document.</returns>
    /// <exception cref="RdfCanonicalizationException">
    /// The context is unknown to an offline loader (fail-closed), could not be retrieved,
    /// or did not resolve to a JSON-LD document.
    /// </exception>
    LoadedContextDocument Load(Uri url);
}
