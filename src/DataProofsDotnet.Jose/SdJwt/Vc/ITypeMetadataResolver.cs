using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// Pluggable hook resolving an SD-JWT VC's <c>vct</c> value to its Type Metadata document
/// (draft-ietf-oauth-sd-jwt-vc-27 §5.3). Per the library-wide external-retrieval posture
/// (PRD FR-10 / FR-17), resolution is offline/local-cache by default and MUST NOT reach the
/// network unless the consumer supplies an implementation that opts into it. A URL-, registry-,
/// or cache-backed implementation is the consumer's choice; the bundled default
/// (<see cref="LocalCacheTypeMetadataResolver"/>) never performs I/O. This hook feeds the unprocessed
/// <see cref="SdJwtVcVerificationResult.TypeMetadata"/>; processing (§5.7) uses
/// <see cref="ITypeMetadataDocumentResolver"/>, which returns the octets integrity is checked over.
/// </summary>
/// <remarks>
/// An implementation that retrieves over HTTP carries the draft's retrieval rules itself, because the
/// verifier only sees the document it returns:
/// <list type="bullet">
/// <item>§3: https URLs only; a bounded number of redirects, never to a non-https URL; every retrieval
/// time-bound and size-bound; the content of a 4xx/5xx response is never used; the content is checked
/// to be a JSON object before use; freshness follows HTTP caching (RFC 9111).</item>
/// <item>§7.1: the <c>vct</c> URL is attacker-chosen input, so validate it, and every redirect target,
/// against server-side request forgery — no loopback, link-local, private-use or other non-globally
/// reachable address, no internal host name, and no public name that resolves to an internal address.</item>
/// <item>§5.3: the returned document's <c>vct</c> must equal the value it was retrieved for.</item>
/// <item>§6: when the credential carries <c>vct#integrity</c>, the retrieved bytes must match it before
/// the document is used.</item>
/// </list>
/// </remarks>
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
