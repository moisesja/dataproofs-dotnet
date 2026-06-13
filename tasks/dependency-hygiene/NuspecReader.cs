using System.IO.Compression;
using System.Xml.Linq;

namespace DataProofsDotnet.Tools.DependencyHygiene;

/// <summary>
/// Reads the DIRECT dependency ids from a packed <c>.nupkg</c> by opening it as a zip archive and
/// parsing the embedded <c>.nuspec</c>'s <c>&lt;dependencies&gt;</c> groups. This is the
/// consumer-facing dependency contract — what a downstream project actually inherits — which a
/// project-graph check (transitive) cannot pin precisely (AC-6 step 3).
/// </summary>
internal static class NuspecReader
{
    /// <summary>Derives the package id from a <c>Id.Version.nupkg</c> filename (best effort).</summary>
    public static string PackageIdFromFileName(string fileName)
    {
        string name = fileName.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase)
            ? fileName[..^".nupkg".Length]
            : fileName;
        // Strip the trailing version: first segment that begins with a digit.
        int cut = -1;
        var parts = name.Split('.');
        for (int i = 0; i < parts.Length; i++)
        {
            if (parts[i].Length > 0 && char.IsDigit(parts[i][0]))
            {
                cut = i;
                break;
            }
        }
        return cut < 0 ? name : string.Join('.', parts[..cut]);
    }

    /// <summary>
    /// Returns the distinct set of direct dependency ids declared across all framework groups in
    /// the package's nuspec. Returns an empty list if no nuspec or no dependencies are present.
    /// </summary>
    public static IReadOnlyList<string> ReadDirectDependencies(string nupkgPath)
    {
        using var archive = ZipFile.OpenRead(nupkgPath);
        var nuspecEntry = archive.Entries.FirstOrDefault(
            e => e.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase));
        if (nuspecEntry is null)
            return [];

        using var stream = nuspecEntry.Open();
        var doc = XDocument.Load(stream);
        XNamespace? ns = doc.Root?.Name.Namespace;

        var ids = new List<string>();
        // <dependency> elements may sit under <dependencies> directly or under <group>; query by
        // local name to be namespace-agnostic.
        foreach (var dependency in doc.Descendants().Where(e => e.Name.LocalName == "dependency"))
        {
            string? id = dependency.Attribute("id")?.Value;
            if (!string.IsNullOrEmpty(id))
                ids.Add(id);
        }

        return ids.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}
