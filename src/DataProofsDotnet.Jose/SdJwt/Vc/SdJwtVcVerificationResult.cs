using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// The structured outcome of SD-JWT VC verification (draft-ietf-oauth-sd-jwt-vc-27 §2.4): the
/// generic SD-JWT verification result enriched with the profile-specific findings — the resolved
/// <c>vct</c>, any retrieved Type Metadata document and, when Type Metadata was processed, the processed
/// metadata. Like the rest of the package, a valid structure that fails a check returns
/// <see cref="IsValid"/> <c>false</c> rather than throwing (PRD FR-3/FR-23); a Type Metadata resolver
/// that throws is reported the same way, and <see cref="TypeMetadataResolverFault"/> tells that fault
/// apart from a verdict. Immutable and thread-safe.
/// </summary>
public sealed class SdJwtVcVerificationResult
{
    private readonly JsonObject? _disclosedPayload;
    private readonly JsonObject? _typeMetadata;

    private SdJwtVcVerificationResult(
        bool isValid,
        JsonObject? disclosedPayload,
        string? vct,
        JsonObject? typeMetadata,
        bool keyBindingVerified,
        IReadOnlyList<string> errors,
        ProcessedTypeMetadata? processedTypeMetadata = null,
        Exception? typeMetadataResolverFault = null)
    {
        IsValid = isValid;
        _disclosedPayload = disclosedPayload;
        Vct = vct;
        _typeMetadata = typeMetadata;
        KeyBindingVerified = keyBindingVerified;
        Errors = errors;
        ProcessedTypeMetadata = processedTypeMetadata;
        TypeMetadataResolverFault = typeMetadataResolverFault;
    }

    /// <summary>True when the SD-JWT verified and every SD-JWT VC profile rule held.</summary>
    public bool IsValid { get; }

    /// <summary>The processed (disclosed) SD-JWT VC payload; <c>null</c> on failure. A defensive clone is returned per access.</summary>
    public JsonObject? DisclosedPayload => _disclosedPayload?.DeepClone() as JsonObject;

    /// <summary>
    /// The verified <c>vct</c> (credential type) value when present; <c>null</c> otherwise. For type matching,
    /// a credential's types are this value and the values of the <c>aka_vcts</c> claim in
    /// <see cref="DisclosedPayload"/>, and no others: Type Metadata and its <c>extends</c> chain do not add
    /// types (draft-ietf-oauth-sd-jwt-vc-27 §2.2.2.2, §5.4).
    /// </summary>
    public string? Vct { get; }

    /// <summary>
    /// The Type Metadata document resolved for <see cref="Vct"/> via the supplied resolver, or
    /// <c>null</c> when no resolver was supplied or the <c>vct</c> was not resolvable (offline
    /// default). A defensive clone is returned per access.
    /// </summary>
    /// <remarks>
    /// From <see cref="SdJwtVcVerifier.VerifyAsync"/>, the document is returned as the resolver gave it. It is not
    /// processed: <c>extends</c> is not followed and claim metadata is not validated against the credential. Before
    /// its contents are used for validation, display or acceptance, draft-ietf-oauth-sd-jwt-vc-27 §5.7 requires full
    /// processing, which <see cref="SdJwtVcVerifier.VerifyWithTypeMetadataAsync"/> performs; there this member holds
    /// the <c>vct</c>'s own document as parsed, and <see cref="ProcessedTypeMetadata"/> the processed result.
    /// </remarks>
    public JsonObject? TypeMetadata => _typeMetadata?.DeepClone() as JsonObject;

    /// <summary>
    /// The processed Type Metadata (draft-ietf-oauth-sd-jwt-vc-27 §5.7): the <c>extends</c> chain applied, claim
    /// metadata merged and validated against the credential, display metadata typed for a wallet. Set only by
    /// <see cref="SdJwtVcVerifier.VerifyWithTypeMetadataAsync"/> on success; <c>null</c> otherwise.
    /// </summary>
    public ProcessedTypeMetadata? ProcessedTypeMetadata { get; }

    /// <summary>
    /// The exception the Type Metadata document resolver threw, when it did; <c>null</c> otherwise. The result is then
    /// invalid with <c>VC_TYPE_METADATA_RESOLVER_FAULT</c>, but that is a retrieval fault, not a verdict on the
    /// credential: the same presentation may verify once retrieval works. Every other failure is a verdict.
    /// </summary>
    public Exception? TypeMetadataResolverFault { get; }

    /// <summary>True when a Key Binding JWT was present and verified.</summary>
    public bool KeyBindingVerified { get; }

    /// <summary>Human-readable failure reasons (empty when <see cref="IsValid"/> is true). No secrets or key material.</summary>
    public IReadOnlyList<string> Errors { get; }

    internal static SdJwtVcVerificationResult Success(JsonObject disclosedPayload, string vct, JsonObject? typeMetadata, bool keyBindingVerified)
        => new(true, disclosedPayload, vct, typeMetadata, keyBindingVerified, []);

    internal static SdJwtVcVerificationResult Success(
        JsonObject disclosedPayload, string vct, JsonObject typeMetadata, ProcessedTypeMetadata processedTypeMetadata, bool keyBindingVerified)
        => new(true, disclosedPayload, vct, typeMetadata, keyBindingVerified, [], processedTypeMetadata);

    internal static SdJwtVcVerificationResult Failure(IReadOnlyList<string> errors)
        => new(false, null, null, null, false, errors);

    internal static SdJwtVcVerificationResult Faulted(string error, Exception fault)
        => new(false, null, null, null, false, [error], typeMetadataResolverFault: fault);

    internal static SdJwtVcVerificationResult Failure(string error)
        => Failure([error]);
}
