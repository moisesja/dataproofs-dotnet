namespace DataProofsDotnet.Cose.Tests.TestSupport;

/// <summary>
/// Fixture access per the PRD §9 conventions: vendored fixtures are copied beside the test
/// binaries and resolved via <see cref="AppContext.BaseDirectory"/> — never fetched at test time.
/// </summary>
internal static class Fixtures
{
    internal static string Root => Path.Combine(AppContext.BaseDirectory, "fixtures");

    internal static string PathOf(params string[] segments) =>
        Path.Combine([Root, .. segments]);

    internal static byte[] Hex(string hex) => Convert.FromHexString(hex.Trim());

    /// <summary>Reads a single-line lowercase-hex fixture file (RFC 8392 vendoring format).</summary>
    internal static byte[] HexFile(params string[] segments) =>
        Hex(File.ReadAllText(PathOf(segments)));

    internal static byte[] Base64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch
        {
            2 => "==",
            3 => "=",
            _ => string.Empty,
        };
        return Convert.FromBase64String(padded);
    }
}
