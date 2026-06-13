namespace DataProofsDotnet.Jose.Jwt;

/// <summary>
/// Validation policy for <see cref="JwtHandler.Verify"/> (PRD FR-15): time-based checks with a
/// configurable clock skew plus expected-value checks for <c>iss</c>/<c>aud</c>/<c>sub</c> and
/// an algorithm allow-list. Immutable after construction (NFR-4).
/// </summary>
public sealed class JwtValidationOptions
{
    /// <summary>
    /// Allowed clock skew applied to <c>exp</c>/<c>nbf</c>/<c>iat</c> comparisons.
    /// Defaults to 60 seconds.
    /// </summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>When set, the token's <c>iss</c> must equal this value exactly.</summary>
    public string? ExpectedIssuer { get; init; }

    /// <summary>When set, the token's <c>aud</c> values must contain this value.</summary>
    public string? ExpectedAudience { get; init; }

    /// <summary>When set, the token's <c>sub</c> must equal this value exactly.</summary>
    public string? ExpectedSubject { get; init; }

    /// <summary>When <c>true</c>, a token without an <c>exp</c> claim is rejected.</summary>
    public bool RequireExpirationTime { get; init; }

    /// <summary>
    /// The JWS algorithms accepted for the token signature. Defaults to the v1 set
    /// (<see cref="JoseAlgorithms.SupportedSignatureAlgorithms"/>); narrow it to pin a single
    /// expected algorithm.
    /// </summary>
    public IReadOnlyList<string> AllowedAlgorithms { get; init; } = JoseAlgorithms.SupportedSignatureAlgorithms;

    /// <summary>
    /// The instant to validate against; <c>null</c> uses <see cref="DateTimeOffset.UtcNow"/>.
    /// Supply a fixed value for deterministic tests.
    /// </summary>
    public DateTimeOffset? CurrentTime { get; init; }
}
