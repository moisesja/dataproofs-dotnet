namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// Retrieves Type Metadata documents as the octets retrieved (draft-ietf-oauth-sd-jwt-vc-27 §5.3), for Type Metadata
/// processing (<see cref="TypeMetadataProcessingOptions"/>). It is called with the credential's <c>vct</c> value and then
/// with each <c>extends</c> value up the chain. The octets are what §6 integrity hashes, which is why this hook returns
/// bytes rather than a parsed object: the library checks <c>vct#integrity</c> and <c>extends#integrity</c> against them,
/// then parses them itself. The FR-10 / FR-17 posture applies: the bundled
/// <see cref="LocalCacheTypeMetadataDocumentResolver"/> never performs I/O, and the library never reaches the network.
/// </summary>
/// <remarks>
/// An implementation that retrieves over HTTP carries the rules listed on <see cref="ITypeMetadataResolver"/> (§3
/// retrieval bounds, §7.1 server-side request forgery). The checks the library makes on what it returns — integrity,
/// <c>vct</c> identity (§5.3), JSON shape, size — need not be repeated, and a resolver must not substitute a document
/// for another reference: a returned document whose <c>vct</c> differs from <c>reference</c> is refused.
/// </remarks>
public interface ITypeMetadataDocumentResolver
{
    /// <summary>
    /// The octets of the Type Metadata document for <paramref name="reference"/>, or <c>null</c> when this resolver does
    /// not know it. Processing then refuses the credential with <c>VC_TYPE_METADATA_UNAVAILABLE</c> (§5.7: processing
    /// that is required and cannot retrieve the metadata rejects). Throw only for a genuine retrieval fault: the verifier
    /// reports a thrown exception as <c>VC_TYPE_METADATA_RESOLVER_FAULT</c>, a fault rather than a verdict.
    /// </summary>
    /// <param name="reference">A <c>vct</c> value, or an <c>extends</c> value of a document already retrieved.</param>
    /// <param name="cancellationToken">Cancels any I/O the implementation performs.</param>
    Task<byte[]?> ResolveDocumentAsync(string reference, CancellationToken cancellationToken = default);
}
