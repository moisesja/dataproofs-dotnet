using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.ApiSurface.Tests;

/// <summary>
/// The Rdfc and Legacy packages carry their own copies of Core's <c>Internal/JsonInputCheck.cs</c>, so they need no
/// <c>InternalsVisibleTo</c> into Core. Every Data Integrity entry point copies and checks its input through that file,
/// so a fix made to one copy and not the others would leave a suite unfixed (PR #62 review: nothing checked them).
/// </summary>
public class VendoredSourceTests
{
    [Theory]
    [InlineData("DataProofsDotnet.Rdfc")]
    [InlineData("DataProofsDotnet.Legacy")]
    public void JsonInputCheck_IsCoresCopy_ApartFromItsNamespaceAndVendoredNote(string package)
    {
        var src = Path.Combine(RepositoryRoot(), "src");
        var core = File.ReadAllLines(Path.Combine(src, "DataProofsDotnet.Core", "Internal", "JsonInputCheck.cs"));
        var copy = File.ReadAllLines(Path.Combine(src, package, "Internal", "JsonInputCheck.cs"));

        copy.Should().Contain($"namespace {package}.Internal;");
        Normalized(copy).Should().Equal(Normalized(core));
    }

    // The namespace line, and the <para> block whose first line names the file it is vendored from.
    private static List<string> Normalized(string[] lines)
    {
        var kept = new List<string>();
        for (var i = 0; i < lines.Length; i++)
        {
            if (lines[i].StartsWith("namespace ", StringComparison.Ordinal))
            {
                continue;
            }

            if (lines[i].Trim() == "/// <para>" && i + 1 < lines.Length && lines[i + 1].Contains("Vendored verbatim from", StringComparison.Ordinal))
            {
                while (lines[i].Trim() != "/// </para>")
                {
                    i++;
                }

                continue;
            }

            kept.Add(lines[i]);
        }

        return kept;
    }

    private static string RepositoryRoot()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "DataProofsDotnet.sln")))
        {
            root = root.Parent;
        }

        root.Should().NotBeNull("the test runs from inside the repository");
        return root!.FullName;
    }
}
