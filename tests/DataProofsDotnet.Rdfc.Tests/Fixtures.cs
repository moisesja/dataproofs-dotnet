namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>Locates vendored fixtures copied beside the test binaries (PRD §9).</summary>
internal static class Fixtures
{
    public static string Root { get; } = Path.Combine(AppContext.BaseDirectory, "fixtures");

    public static string PathTo(params string[] parts)
        => Path.Combine([Root, .. parts]);

    public static string ReadText(params string[] parts)
        => File.ReadAllText(PathTo(parts));
}
