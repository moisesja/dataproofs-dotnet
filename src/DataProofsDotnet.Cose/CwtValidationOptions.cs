namespace DataProofsDotnet.Cose;

/// <summary>
/// Options controlling CWT claims validation (<see cref="Cwt.Verify"/>).
/// Immutable after construction (init-only).
/// </summary>
public sealed class CwtValidationOptions
{
    /// <summary>
    /// The instant against which exp/nbf are evaluated. Defaults to the current UTC time when
    /// <see langword="null"/>.
    /// </summary>
    public DateTimeOffset? ValidationTime { get; init; }

    /// <summary>
    /// Allowed clock skew applied symmetrically to exp and nbf. Defaults to zero (strict).
    /// Must not be negative.
    /// </summary>
    public TimeSpan ClockSkew { get; init; }
}
