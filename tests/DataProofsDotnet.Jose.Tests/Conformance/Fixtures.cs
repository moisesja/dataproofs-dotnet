using System.Text.Json;

namespace DataProofsDotnet.Jose.Tests.Conformance;

/// <summary>
/// Vendored-fixture access (PRD §9 conventions): fixtures are copied beside the test binaries
/// and read via <c>Path.Combine(AppContext.BaseDirectory, "fixtures", …)</c>; CI runs offline
/// with respect to fixtures.
/// </summary>
internal static class Fixtures
{
    public static string PathOf(params string[] segments)
        => Path.Combine([AppContext.BaseDirectory, "fixtures", .. segments]);

    public static JsonDocument LoadJson(params string[] segments)
        => JsonDocument.Parse(File.ReadAllText(PathOf(segments)));

    /// <summary>Deserialize a JSON element carrying a JWK object into the library's <see cref="Jwk"/> model.</summary>
    public static Jwk ToJwk(JsonElement element)
        => JsonSerializer.Deserialize<Jwk>(element.GetRawText())!;
}
