using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// The structured outcome of SD-JWT VC verification (draft-ietf-oauth-sd-jwt-vc-16 §3.5): the
/// generic SD-JWT verification result enriched with the profile-specific findings — the resolved
/// <c>vct</c> and any retrieved Type Metadata document. Like the rest of the package, a valid
/// structure that fails a check returns <see cref="IsValid"/> <c>false</c> rather than throwing
/// (PRD FR-3/FR-23). Immutable and thread-safe.
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
        IReadOnlyList<string> errors)
    {
        IsValid = isValid;
        _disclosedPayload = disclosedPayload;
        Vct = vct;
        _typeMetadata = typeMetadata;
        KeyBindingVerified = keyBindingVerified;
        Errors = errors;
    }

    /// <summary>True when the SD-JWT verified and every SD-JWT VC profile rule held.</summary>
    public bool IsValid { get; }

    /// <summary>The processed (disclosed) SD-JWT VC payload; <c>null</c> on failure. A defensive clone is returned per access.</summary>
    public JsonObject? DisclosedPayload => _disclosedPayload?.DeepClone() as JsonObject;

    /// <summary>The verified <c>vct</c> (credential type) value when present; <c>null</c> otherwise.</summary>
    public string? Vct { get; }

    /// <summary>
    /// The Type Metadata document resolved for <see cref="Vct"/> via the supplied resolver, or
    /// <c>null</c> when no resolver was supplied or the <c>vct</c> was not resolvable (offline
    /// default). A defensive clone is returned per access.
    /// </summary>
    public JsonObject? TypeMetadata => _typeMetadata?.DeepClone() as JsonObject;

    /// <summary>True when a Key Binding JWT was present and verified.</summary>
    public bool KeyBindingVerified { get; }

    /// <summary>Human-readable failure reasons (empty when <see cref="IsValid"/> is true). No secrets or key material.</summary>
    public IReadOnlyList<string> Errors { get; }

    internal static SdJwtVcVerificationResult Success(JsonObject disclosedPayload, string vct, JsonObject? typeMetadata, bool keyBindingVerified)
        => new(true, disclosedPayload, vct, typeMetadata, keyBindingVerified, []);

    internal static SdJwtVcVerificationResult Failure(IReadOnlyList<string> errors)
        => new(false, null, null, null, false, errors);

    internal static SdJwtVcVerificationResult Failure(string error)
        => Failure([error]);
}
