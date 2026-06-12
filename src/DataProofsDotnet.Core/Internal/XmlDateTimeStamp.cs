using System.Globalization;
using System.Text.RegularExpressions;

namespace DataProofsDotnet.Internal;

/// <summary>
/// Lexical validation and parsing of XML Schema 1.1 <c>dateTimeStamp</c> values, the
/// timestamp form VC Data Integrity 1.0 requires for <c>created</c>/<c>expires</c>
/// (an ISO 8601 date-time with a mandatory timezone designator).
/// </summary>
internal static partial class XmlDateTimeStamp
{
    [GeneratedRegex(@"^-?\d{4,}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")]
    private static partial Regex LexicalForm();

    /// <summary>
    /// Parses <paramref name="value"/> as a dateTimeStamp. Returns <c>false</c> for any
    /// value missing an explicit timezone or otherwise outside the lexical space.
    /// </summary>
    public static bool TryParse(string? value, out DateTimeOffset result)
    {
        result = default;
        return value is not null
            && LexicalForm().IsMatch(value)
            && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out result);
    }
}
