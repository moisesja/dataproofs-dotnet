using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// Pluggable hook resolving an SD-JWT VC's <c>vct</c> value to its Type Metadata document
/// (draft-ietf-oauth-sd-jwt-vc-16 §6). Per the library-wide external-retrieval posture
/// (PRD FR-10 / FR-17), resolution is offline/local-cache by default and MUST NOT reach the
/// network unless the consumer supplies an implementation that opts into it. A URL-, registry-,
/// or cache-backed implementation is the consumer's choice; the bundled default
/// (<see cref="LocalCacheTypeMetadataResolver"/>) never performs I/O.
/// </summary>
public interface ITypeMetadataResolver
{
    /// <summary>
    /// Resolve the Type Metadata document for <paramref name="vct"/>, or <c>null</c> when this
    /// resolver does not know the type (a closed/offline resolver returns <c>null</c> rather than
    /// reaching out). Implementations MUST NOT throw on an unknown <c>vct</c>; reserve exceptions
    /// for genuine retrieval faults the consumer opted into.
    /// </summary>
    /// <param name="vct">The credential's <c>vct</c> claim value.</param>
    /// <param name="cancellationToken">Cancels any I/O the implementation performs.</param>
    Task<JsonObject?> ResolveAsync(string vct, CancellationToken cancellationToken = default);
}
