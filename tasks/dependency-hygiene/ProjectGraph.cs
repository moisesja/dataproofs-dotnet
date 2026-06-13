using System.Xml.Linq;

namespace DataProofsDotnet.Tools.DependencyHygiene;

/// <summary>
/// Resolves the transitive set of sibling project ids a given .csproj references via
/// <c>&lt;ProjectReference&gt;</c>. Needed because <c>dotnet list package</c> surfaces only NuGet
/// packages, never ProjectReferences — so the project-graph closure shows dotNetRDF flowing into
/// the DI package without showing the <c>DataProofsDotnet.Rdfc</c> ProjectReference that legitimately
/// mediates it (PRD §2.2: the DI package "may reference all of the above", including Rdfc).
/// </summary>
internal static class ProjectGraph
{
    /// <summary>
    /// Returns the set of project ids (filename without extension) reachable from
    /// <paramref name="csprojPath"/> through ProjectReference chains, INCLUDING the project itself.
    /// </summary>
    public static HashSet<string> TransitiveProjectIds(string csprojPath)
    {
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Walk(Path.GetFullPath(csprojPath), visited, ids);
        return ids;
    }

    private static void Walk(string csprojPath, HashSet<string> visited, HashSet<string> ids)
    {
        if (!visited.Add(csprojPath) || !File.Exists(csprojPath))
            return;

        ids.Add(Path.GetFileNameWithoutExtension(csprojPath));

        XDocument doc;
        try
        {
            doc = XDocument.Load(csprojPath);
        }
        catch
        {
            return; // unreadable csproj — best effort
        }

        string baseDir = Path.GetDirectoryName(csprojPath)!;
        foreach (var reference in doc.Descendants().Where(e => e.Name.LocalName == "ProjectReference"))
        {
            string? include = reference.Attribute("Include")?.Value;
            if (string.IsNullOrEmpty(include))
                continue;

            // ProjectReference paths use Windows-style separators in some csprojs; normalize.
            string relative = include.Replace('\\', Path.DirectorySeparatorChar);
            string resolved = Path.GetFullPath(Path.Combine(baseDir, relative));
            Walk(resolved, visited, ids);
        }
    }
}
