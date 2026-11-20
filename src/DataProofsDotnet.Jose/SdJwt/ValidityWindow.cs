using System.Text.Json;
using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// The SD-JWT validity window (RFC 9901 §7.1 step 6: "Check that the SD-JWT is valid using claims such as nbf, exp,
/// and aud in the processed payload, if present"): the top-level <c>nbf</c> and <c>exp</c> members as RFC 7519
/// NumericDates (§2, §4.1.4, §4.1.5), judged against a reference instant with a clock skew. Both claims are optional;
/// a present one must be a JSON number of seconds that <see cref="DateTimeOffset"/> can represent. Internal: the
/// verifier judges the window, the issuer only the shape.
/// </summary>
internal static class ValidityWindow
{
    /// <summary>The current time is at or past <c>exp</c> + skew.</summary>
    public const string ExpiredCode = "SD_JWT_EXPIRED";

    /// <summary>The current time is before <c>nbf</c> − skew.</summary>
    public const string NotYetValidCode = "SD_JWT_NOT_YET_VALID";

    /// <summary>A present <c>exp</c> is not a NumericDate.</summary>
    public const string ExpInvalidCode = "SD_JWT_EXP_INVALID";

    /// <summary>A present <c>nbf</c> is not a NumericDate.</summary>
    public const string NbfInvalidCode = "SD_JWT_NBF_INVALID";

    private const string ExpClaim = "exp";
    private const string NbfClaim = "nbf";

    // The whole seconds DateTimeOffset represents, the bounds JwtClaims and the KB-JWT 'iat' use. With a fraction
    // rounded to the tick toward either side, a value inside them stays inside DateTimeOffset's range.
    private const long MinUnixSeconds = -62135596800L; // 0001-01-01T00:00:00Z
    private const long MaxUnixSeconds = 253402300799L; // 9999-12-31T23:59:59Z

    private static readonly long UnixEpochTicks = DateTimeOffset.UnixEpoch.UtcTicks;

    /// <summary>
    /// Judges the top-level <c>nbf</c> and <c>exp</c> of <paramref name="payload"/> at <paramref name="now"/>. Returns
    /// the failures, coded, one per claim at most; empty when each claim is absent or inside the window.
    /// </summary>
    /// <remarks>
    /// <c>exp</c> fails when <c>now − exp ≥ skew</c>: RFC 7519 §4.1.4, "the current date/time MUST be before the
    /// expiration date/time", so with no skew the instant <c>exp</c> itself is refused. <c>nbf</c> fails when
    /// <c>nbf − now &gt; skew</c>: §4.1.5, "after or equal", the comparison the Key Binding JWT <c>iat</c> check makes.
    /// Each side subtracts two <see cref="DateTimeOffset"/> values, which are less than 3.2e18 ticks apart, and compares
    /// <see cref="TimeSpan"/>s, so no instant and no skew overflows. A negative skew narrows the window on both sides.
    /// </remarks>
    public static IReadOnlyList<string> Check(JsonObject payload, DateTimeOffset now, TimeSpan skew)
    {
        var errors = new List<string>(2);

        if (!TryRead(payload, NbfClaim, roundUp: true, out var nbf))
            errors.Add(InvalidMessage(NbfInvalidCode, NbfClaim));
        else if (nbf is { } notBefore && notBefore - now > skew)
            errors.Add($"{NotYetValidCode}: the SD-JWT is not valid before {notBefore:O} ('nbf', clock skew {skew}; RFC 7519 §4.1.5).");

        if (!TryRead(payload, ExpClaim, roundUp: false, out var exp))
            errors.Add(InvalidMessage(ExpInvalidCode, ExpClaim));
        else if (exp is { } expiry && now - expiry >= skew)
            errors.Add($"{ExpiredCode}: the SD-JWT expired at {expiry:O} ('exp', clock skew {skew}; RFC 7519 §4.1.4).");

        return errors;
    }

    /// <summary>
    /// The first top-level <c>nbf</c> or <c>exp</c> of <paramref name="payload"/> that is present and not a NumericDate,
    /// as the verifier's message; <c>null</c> when both are absent or well formed. The time is not judged.
    /// </summary>
    public static string? ShapeViolation(JsonObject payload)
    {
        if (!TryRead(payload, NbfClaim, roundUp: true, out _))
            return InvalidMessage(NbfInvalidCode, NbfClaim);
        if (!TryRead(payload, ExpClaim, roundUp: false, out _))
            return InvalidMessage(ExpInvalidCode, ExpClaim);
        return null;
    }

    private static string InvalidMessage(string code, string claim)
        => $"{code}: SD-JWT '{claim}' must be a NumericDate, a JSON number of seconds since the epoch within "
           + $"{MinUnixSeconds} to {MaxUnixSeconds} (RFC 7519 §2, §4.1).";

    /// <summary>
    /// Reads the top-level member <paramref name="name"/>. <c>true</c> with a <c>null</c> instant when it is absent (both
    /// claims are optional); <c>true</c> with the instant when it is a NumericDate in range; <c>false</c> otherwise:
    /// a string, boolean, <c>null</c>, array or object, or a number out of range, including one <see cref="decimal"/>
    /// cannot hold, such as <c>1e400</c>.
    /// </summary>
    /// <param name="payload">The payload. Its values are parsed JSON, which <see cref="JsonValue.TryGetValue{T}"/> reads as <see cref="decimal"/>.</param>
    /// <param name="name">The claim name.</param>
    /// <param name="roundUp">
    /// A fraction is kept to the 100 ns tick, and a remainder below one tick is rounded toward refusal: up for
    /// <c>nbf</c>, down for <c>exp</c>.
    /// </param>
    /// <param name="instant">The instant, when present and valid.</param>
    private static bool TryRead(JsonObject payload, string name, bool roundUp, out DateTimeOffset? instant)
    {
        instant = null;
        if (!payload.TryGetPropertyValue(name, out var node))
            return true;

        if (node is not JsonValue value
            || value.GetValueKind() != JsonValueKind.Number
            || !value.TryGetValue<decimal>(out var seconds)
            || seconds < MinUnixSeconds
            || seconds > MaxUnixSeconds)
        {
            return false;
        }

        var ticks = seconds * TimeSpan.TicksPerSecond;
        ticks = roundUp ? decimal.Ceiling(ticks) : decimal.Floor(ticks);
        instant = new DateTimeOffset(UnixEpochTicks + (long)ticks, TimeSpan.Zero);
        return true;
    }
}
