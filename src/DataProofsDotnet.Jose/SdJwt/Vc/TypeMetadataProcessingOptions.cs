namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// Turns on SD-JWT VC Type Metadata processing (draft-ietf-oauth-sd-jwt-vc-27 §5.7) for
/// <see cref="SdJwtVcVerifier.VerifyWithTypeMetadataAsync"/> and <see cref="SdJwtVcIssuer.IssueWithTypeMetadataAsync"/>.
/// Processing is then required: metadata that cannot be retrieved or processed rejects the credential, as §5.7 says it
/// must when "Type Metadata processing is required by policy". Immutable once built; thread-safe.
/// </summary>
public sealed class TypeMetadataProcessingOptions
{
    /// <summary>The default for <see cref="MaxExtendsDepth"/>: eight <c>extends</c> hops.</summary>
    public const int DefaultMaxExtendsDepth = 8;

    /// <summary>The default for <see cref="MaxDocumentSize"/>: 1 MiB.</summary>
    public const int DefaultMaxDocumentSize = 1024 * 1024;

    private readonly int _maxExtendsDepth = DefaultMaxExtendsDepth;
    private readonly int _maxDocumentSize = DefaultMaxDocumentSize;

    /// <summary>Create processing options over <paramref name="resolver"/>.</summary>
    /// <param name="resolver">Retrieves each document's octets: the <c>vct</c>'s, then each <c>extends</c> parent's.</param>
    public TypeMetadataProcessingOptions(ITypeMetadataDocumentResolver resolver)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        Resolver = resolver;
    }

    /// <summary>The document resolver. The library itself never retrieves anything (FR-10 / FR-17).</summary>
    public ITypeMetadataDocumentResolver Resolver { get; }

    /// <summary>
    /// The most <c>extends</c> hops followed from the <c>vct</c>'s document (0 allows no parent). A longer chain fails
    /// with <c>VC_TYPE_METADATA_EXTENDS_DEPTH</c>; a chain that returns to a type already in it fails with
    /// <c>VC_TYPE_METADATA_EXTENDS_CYCLE</c> (§7.4). Defaults to <see cref="DefaultMaxExtendsDepth"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When set to a negative value.</exception>
    public int MaxExtendsDepth
    {
        get => _maxExtendsDepth;
        init => _maxExtendsDepth = value >= 0 ? value : throw new ArgumentOutOfRangeException(nameof(value), "MaxExtendsDepth must be non-negative.");
    }

    /// <summary>
    /// The largest document, in octets, that is processed; a larger one fails with <c>VC_TYPE_METADATA_INVALID</c>.
    /// The resolver bounds its own retrieval (§3); this bounds what processing parses. Defaults to
    /// <see cref="DefaultMaxDocumentSize"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When set to a value below 1.</exception>
    public int MaxDocumentSize
    {
        get => _maxDocumentSize;
        init => _maxDocumentSize = value >= 1 ? value : throw new ArgumentOutOfRangeException(nameof(value), "MaxDocumentSize must be positive.");
    }
}
