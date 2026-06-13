namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// Policy controlling SD-JWT verification and the Key Binding JWT checks (RFC 9901 §7.3).
/// Immutable; defaults are the strict posture (a present KB-JWT is always cryptographically
/// verified; <see cref="RequireKeyBinding"/> additionally makes its absence a failure).
/// </summary>
public sealed record SdJwtVerificationOptions
{
    /// <summary>
    /// When <c>true</c>, a presentation that carries no Key Binding JWT fails verification. When
    /// <c>false</c> (the default), a KB-JWT is verified if present but is not required. Set this
    /// when the SD-JWT carries a <c>cnf</c> key and the Verifier demands holder proof-of-possession.
    /// </summary>
    public bool RequireKeyBinding { get; init; }

    /// <summary>
    /// The audience the KB-JWT's <c>aud</c> must equal (the Verifier's own identifier). When a
    /// KB-JWT is verified this is REQUIRED; a <c>null</c> value with a present KB-JWT fails
    /// (RFC 9901 §7.3 — the Verifier MUST check it is the intended audience).
    /// </summary>
    public string? ExpectedAudience { get; init; }

    /// <summary>
    /// The nonce the KB-JWT's <c>nonce</c> must equal (the Verifier-supplied freshness/replay
    /// value). When a KB-JWT is verified this is REQUIRED; a <c>null</c> value with a present
    /// KB-JWT fails (RFC 9901 §7.3 / §10 replay defense).
    /// </summary>
    public string? ExpectedNonce { get; init; }

    /// <summary>
    /// The maximum age of the KB-JWT measured from its <c>iat</c> to <see cref="CurrentTime"/>.
    /// When set, a KB-JWT whose <c>iat</c> is older than this (allowing <see cref="ClockSkew"/>)
    /// fails — a freshness bound against replay (RFC 9901 §10). <c>null</c> disables the age check.
    /// </summary>
    public TimeSpan? MaxKeyBindingAge { get; init; }

    /// <summary>Permitted clock skew applied to KB-JWT <c>iat</c> freshness checks. Defaults to 2 minutes.</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>The reference "now" for freshness checks; <c>null</c> uses <see cref="DateTimeOffset.UtcNow"/> at verify time.</summary>
    public DateTimeOffset? CurrentTime { get; init; }
}
