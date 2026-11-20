using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// The structured outcome of SD-JWT verification (RFC 9901 §7). Following the same convention as
/// the rest of the package (<see cref="Jwt.JwtVerificationResult"/>, PRD FR-3/FR-23), an SD-JWT
/// that is structurally valid but fails a verification check returns a result with
/// <see cref="IsValid"/> <c>false</c> and a populated <see cref="Errors"/> list — it does not
/// throw. Exceptions (<see cref="MalformedJoseException"/>) are reserved for inputs so malformed
/// that no result can be produced (e.g. a non-JWT first element). Immutable and thread-safe.
/// </summary>
public sealed class SdJwtVerificationResult
{
    private readonly JsonObject? _disclosedPayload;

    private SdJwtVerificationResult(
        bool isValid,
        JsonObject? disclosedPayload,
        IReadOnlyList<string> errors,
        bool keyBindingVerified,
        string? signatureAlgorithm)
    {
        IsValid = isValid;
        _disclosedPayload = disclosedPayload;
        Errors = errors;
        KeyBindingVerified = keyBindingVerified;
        SignatureAlgorithm = signatureAlgorithm;
    }

    /// <summary>True when the issuer signature verified, every disclosure resolved, and (when required) Key Binding passed.</summary>
    public bool IsValid { get; }

    /// <summary>
    /// The processed (disclosed) SD-JWT payload (RFC 9901 §7.1) with all <c>_sd</c>/<c>...</c>
    /// placeholders resolved and the control claims (<c>_sd</c>, <c>_sd_alg</c>) stripped.
    /// <c>null</c> when verification failed before reconstruction completed. A defensive clone is
    /// returned on each access.
    /// </summary>
    public JsonObject? DisclosedPayload => _disclosedPayload?.DeepClone() as JsonObject;

    /// <summary>Human-readable failure reasons (empty when <see cref="IsValid"/> is true). No secrets or key material.</summary>
    public IReadOnlyList<string> Errors { get; }

    /// <summary>True when a Key Binding JWT was present and successfully verified (<c>sd_hash</c>/<c>aud</c>/<c>nonce</c>/<c>typ</c>/signature).</summary>
    public bool KeyBindingVerified { get; }

    /// <summary>The issuer JWT's signature algorithm when known; <c>null</c> otherwise.</summary>
    public string? SignatureAlgorithm { get; }

    internal static SdJwtVerificationResult Success(JsonObject disclosedPayload, bool keyBindingVerified, string signatureAlgorithm)
        => new(true, disclosedPayload, [], keyBindingVerified, signatureAlgorithm);

    internal static SdJwtVerificationResult Failure(IReadOnlyList<string> errors, string? signatureAlgorithm = null)
        => new(false, null, errors, false, signatureAlgorithm);

    internal static SdJwtVerificationResult Failure(string error, string? signatureAlgorithm = null)
        => Failure([error], signatureAlgorithm);
}
