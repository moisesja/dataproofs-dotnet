using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// The validity window of a JWT in an SD-JWT presentation: the top-level <c>nbf</c> and <c>exp</c> members as RFC 7519
/// NumericDates (§2, §4.1.4, §4.1.5), judged against a reference instant with a clock skew. For the SD-JWT it is RFC
/// 9901 §7.1 step 6 ("Check that the SD-JWT is valid using claims such as nbf, exp, and aud in the processed payload,
/// if present"); for the Key Binding JWT, §7.3 step 5.h ("a valid JWT in all other respects, per [RFC7519]"). Both
/// claims are optional; a present one must be a JSON number of seconds from <see cref="MinUnixSeconds"/> to
/// <see cref="MaxUnixSeconds"/>. Internal: the verifier judges the window, the issuer only the shape.
/// </summary>
internal static class ValidityWindow
{
    /// <summary>The SD-JWT's codes: <c>SD_JWT_EXPIRED</c>, <c>SD_JWT_NOT_YET_VALID</c>, <c>SD_JWT_EXP_INVALID</c>, <c>SD_JWT_NBF_INVALID</c>.</summary>
    public static readonly Codes SdJwt = new("SD_JWT", "the SD-JWT");

    /// <summary>
    /// The Key Binding JWT's codes: <c>KB_JWT_EXPIRED</c> (shared with the <c>iat</c> age bound: either way the KB-JWT
    /// is too old to accept), <c>KB_JWT_NOT_YET_VALID</c>, <c>KB_JWT_EXP_INVALID</c>, <c>KB_JWT_NBF_INVALID</c>.
    /// </summary>
    public static readonly Codes KeyBindingJwt = new("KB_JWT", "the Key Binding JWT");

    /// <summary>The code prefix and the noun a message names.</summary>
    internal sealed record Codes(string Prefix, string Subject)
    {
        /// <summary>The current time is at or past <c>exp</c> + skew.</summary>
        public string Expired => Prefix + "_EXPIRED";

        /// <summary>The current time is before <c>nbf</c> − skew.</summary>
        public string NotYetValid => Prefix + "_NOT_YET_VALID";

        /// <summary>A present <c>exp</c> is not a NumericDate.</summary>
        public string ExpInvalid => Prefix + "_EXP_INVALID";

        /// <summary>A present <c>nbf</c> is not a NumericDate.</summary>
        public string NbfInvalid => Prefix + "_NBF_INVALID";
    }

    private const string ExpClaim = "exp";
    private const string NbfClaim = "nbf";

    /// <summary>0001-01-01T00:00:00Z: the first whole second <see cref="DateTimeOffset"/> represents.</summary>
    public const long MinUnixSeconds = -62135596800L;

    /// <summary>9999-12-31T23:59:59Z: the last whole second <see cref="DateTimeOffset"/> represents.</summary>
    /// <remarks>
    /// The bounds <c>JwtClaims</c> and the KB-JWT <c>iat</c> use. A value inside them, its fraction rounded to the tick
    /// either way, stays inside <see cref="DateTimeOffset"/>'s range.
    /// </remarks>
    public const long MaxUnixSeconds = 253402300799L;

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
    public static IReadOnlyList<string> Check(JsonObject payload, DateTimeOffset now, TimeSpan skew, Codes codes)
    {
        var errors = new List<string>(2);

        if (!TryRead(payload, NbfClaim, roundUp: true, out var nbf))
            errors.Add(InvalidMessage(codes.NbfInvalid, codes, NbfClaim));
        else if (nbf is { } notBefore && notBefore - now > skew)
            errors.Add($"{codes.NotYetValid}: {codes.Subject} is not valid before {notBefore:O} ('nbf', clock skew {skew}; RFC 7519 §4.1.5).");

        if (!TryRead(payload, ExpClaim, roundUp: false, out var exp))
            errors.Add(InvalidMessage(codes.ExpInvalid, codes, ExpClaim));
        else if (exp is { } expiry && now - expiry >= skew)
            errors.Add($"{codes.Expired}: {codes.Subject} expired at {expiry:O} ('exp', clock skew {skew}; RFC 7519 §4.1.4).");

        return errors;
    }

    /// <summary>
    /// The first top-level <c>nbf</c> or <c>exp</c> of <paramref name="payload"/> that is present and not a NumericDate,
    /// as the verifier's <see cref="SdJwt"/> message; <c>null</c> when both are absent or well formed. The time is not judged.
    /// </summary>
    public static string? ShapeViolation(JsonObject payload)
    {
        if (!TryRead(payload, NbfClaim, roundUp: true, out _))
            return InvalidMessage(SdJwt.NbfInvalid, SdJwt, NbfClaim);
        if (!TryRead(payload, ExpClaim, roundUp: false, out _))
            return InvalidMessage(SdJwt.ExpInvalid, SdJwt, ExpClaim);
        return null;
    }

    private static string InvalidMessage(string code, Codes codes, string claim)
        => $"{code}: {codes.Subject} '{claim}' must be a NumericDate, a JSON number of seconds since the epoch from "
           + $"{MinUnixSeconds} to {MaxUnixSeconds} (RFC 7519 §2, §4.1).";

    /// <summary>
    /// Reads the top-level member <paramref name="name"/>. <c>true</c> with a <c>null</c> instant when it is absent (both
    /// claims are optional); <c>true</c> with the instant when it is a NumericDate in range; <c>false</c> otherwise:
    /// a string, boolean, <c>null</c>, array or object, or a number out of range, including one <see cref="decimal"/>
    /// cannot hold, such as <c>1e400</c>.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="name">The claim name.</param>
    /// <param name="roundUp">
    /// A fraction is kept to the 100 ns tick, with a remainder below one tick rounded toward refusal: up for <c>nbf</c>,
    /// down for <c>exp</c>. The number is read at <see cref="decimal"/> precision first (28 to 29 significant digits,
    /// rounded to nearest), so a fraction beyond that, some 1e-18 s at today's dates, is not exact.
    /// </param>
    /// <param name="instant">The instant, when present and valid.</param>
    private static bool TryRead(JsonObject payload, string name, bool roundUp, out DateTimeOffset? instant)
    {
        instant = null;
        if (!payload.TryGetPropertyValue(name, out var node))
            return true;

        if (node is not JsonValue value
            || value.GetValueKind() != JsonValueKind.Number
            || !TryGetSeconds(value, out var seconds)
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

    /// <summary>
    /// The number as <see cref="decimal"/>. A parsed value, which is every payload the verifier reads, converts directly,
    /// exactly for the decimal text a JWT carries. A value that wraps a .NET number converts only if it is a
    /// <see cref="decimal"/>, so it is read as the JSON text it serializes to, which is what would be signed; a
    /// non-finite <see cref="double"/> has none and is refused.
    /// </summary>
    private static bool TryGetSeconds(JsonValue value, out decimal seconds)
    {
        if (value.TryGetValue(out seconds))
            return true;

        string text;
        try
        {
            text = value.ToJsonString();
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or NotSupportedException)
        {
            seconds = 0;
            return false;
        }
        return decimal.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out seconds);
    }
}
