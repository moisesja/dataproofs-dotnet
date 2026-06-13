using System.Text.RegularExpressions;

namespace DataProofsDotnet.Tools.ParityDiff;

/// <summary>One ported-file → didcomm-source-file pair from PARITY.md's file map.</summary>
internal sealed record FilePair(string PortedFile, string SourcePath);

/// <summary>
/// One rename-map entry. A <see cref="StructuralAdaptation"/> entry's RHS is prose, not a code
/// token (it documents a sanctioned shape change such as reading a JSON payload property); a
/// plain token rename's RHS is a code fragment substituted into the source assertion text.
/// </summary>
internal sealed record RenameEntry(string Old, string New, bool StructuralAdaptation);

/// <summary>
/// Parses PARITY.md (AC-5 setup contract): the source SHA, the file-map table (ported → source),
/// and the machine-readable rename map fenced as <c>```parity-rename-map</c>.
/// </summary>
internal sealed class ParityManifest
{
    public required string SourceSha { get; init; }
    public required IReadOnlyList<FilePair> Pairs { get; init; }
    public required IReadOnlyList<RenameEntry> Renames { get; init; }

    /// <summary>
    /// Source test-method names (the method identifier, no class prefix) that PARITY.md's
    /// "Intentionally omitted source tests" section sanctions as NOT ported. Assertions inside
    /// these methods are excluded from the strict diff. (Whole-file omissions never appear in the
    /// file map, so they need no further handling.)
    /// </summary>
    public required IReadOnlySet<string> OmittedTestMethods { get; init; }

    private static readonly Regex ShaRegex =
        new(@"\*\*Source commit SHA:\*\*\s*`([0-9a-fA-F]{7,40})`", RegexOptions.Compiled);

    public static ParityManifest Parse(string parityMdPath)
    {
        string text = File.ReadAllText(parityMdPath);
        var lines = File.ReadAllLines(parityMdPath);

        var shaMatch = ShaRegex.Match(text);
        if (!shaMatch.Success)
            throw new InvalidOperationException("PARITY.md: could not find the **Source commit SHA:** `<sha>` line.");
        string sha = shaMatch.Groups[1].Value;

        var pairs = ParseFileMap(lines);
        var renames = ParseRenameMap(lines);
        var omitted = ParseOmittedTests(lines);

        return new ParityManifest
        {
            SourceSha = sha,
            Pairs = pairs,
            Renames = renames,
            OmittedTestMethods = omitted,
        };
    }

    // The "## Intentionally omitted source tests" section lists, in a markdown table, the source
    // tests not ported. Method-level omissions appear as backticked `Class.Method` (or
    // `Class.Method` and `…_other`) identifiers; whole-file omissions appear as `Path/File.cs`.
    // We harvest the method identifiers (the trailing PascalCase/underscore name after the last
    // '.') and any "…_suffix" continuation that shares the preceding method's stem.
    private static HashSet<string> ParseOmittedTests(string[] lines)
    {
        var omitted = new HashSet<string>(StringComparer.Ordinal);
        bool inSection = false;

        foreach (var raw in lines)
        {
            var line = raw.Trim();

            if (line.StartsWith("## ", StringComparison.Ordinal))
            {
                inSection = line.Contains("Intentionally omitted", StringComparison.OrdinalIgnoreCase);
                continue;
            }
            if (!inSection || !line.StartsWith("|"))
                continue;

            foreach (Match m in Regex.Matches(line, "`([^`]+)`"))
            {
                string token = m.Groups[1].Value.Trim();

                // Whole-file omission (a path) — skip; it never appears in the file map.
                if (token.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
                    continue;

                // "…_passes_when_present" continuation of the previous method's stem. Store the
                // bare suffix fragment (no leading ellipsis/underscore) so IsOmittedMethod's
                // "_<fragment>" suffix match excludes the sibling method whose elided stem matches.
                if (token.StartsWith('…') || token.StartsWith("..."))
                {
                    string suffix = token.TrimStart('…', '.', '_');
                    if (suffix.Length > 0)
                        omitted.Add(suffix);
                    continue;
                }

                // A Class.Method (or deeper) identifier: take the trailing method name.
                int dot = token.LastIndexOf('.');
                string method = dot >= 0 ? token[(dot + 1)..] : token;
                if (method.Length == 0)
                    continue;
                omitted.Add(method);
            }
        }

        return omitted;
    }

    // The file map is the markdown table whose header mentions "Ported file" and "Source path".
    // Each data row: | `Ported.cs` | `Source/Path.cs` |  — we take .cs rows that have a real
    // source path (skip support rows whose source cell is "—" or prose).
    private static List<FilePair> ParseFileMap(string[] lines)
    {
        var pairs = new List<FilePair>();
        bool inTable = false;

        foreach (var raw in lines)
        {
            var line = raw.Trim();

            if (line.StartsWith("| Ported file", StringComparison.OrdinalIgnoreCase))
            {
                inTable = true;
                continue;
            }
            if (!inTable)
                continue;

            // Table separator row (|---|---|) — skip.
            if (line.StartsWith("|") && line.Replace("|", "").Replace("-", "").Replace(":", "").Trim().Length == 0)
                continue;

            // End of the table.
            if (!line.StartsWith("|"))
            {
                if (pairs.Count > 0)
                    break;
                inTable = false;
                continue;
            }

            var cells = line.Trim('|').Split('|');
            if (cells.Length < 2)
                continue;

            string ported = ExtractBacktickedCs(cells[0]);
            string source = ExtractBacktickedCs(cells[1]);

            // Skip support/seam rows: source cell is "—" / empty / not a .cs path.
            if (ported.Length == 0 || source.Length == 0)
                continue;
            if (!source.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
                continue;
            // Skip the GlobalUsings support row (lives outside Parity/, no assertions to diff).
            if (ported.Contains("GlobalUsings", StringComparison.OrdinalIgnoreCase))
                continue;

            pairs.Add(new FilePair(ported, source));
        }

        if (pairs.Count == 0)
            throw new InvalidOperationException("PARITY.md: file-map table produced no ported→source pairs.");
        return pairs;
    }

    // Pulls the first `…` token from a table cell and returns it only if it ends in .cs.
    private static string ExtractBacktickedCs(string cell)
    {
        var m = Regex.Match(cell, "`([^`]+)`");
        if (!m.Success)
            return string.Empty;
        string inner = m.Groups[1].Value.Trim();
        // Some ported cells carry a trailing "(support)" note outside the backticks — already gone.
        return inner;
    }

    // The rename map sits inside a ```parity-rename-map fenced block, one "old -> new" per line,
    // with '#' comments (which may also carry an inline "# note" after the mapping).
    private static List<RenameEntry> ParseRenameMap(string[] lines)
    {
        var renames = new List<RenameEntry>();
        bool inFence = false;

        foreach (var raw in lines)
        {
            var line = raw;

            if (!inFence)
            {
                if (line.TrimStart().StartsWith("```parity-rename-map", StringComparison.Ordinal))
                    inFence = true;
                continue;
            }

            if (line.TrimStart().StartsWith("```", StringComparison.Ordinal))
                break; // end of fence

            // Strip a trailing inline comment ("# note") but keep the mapping before it.
            string body = line;
            int hash = body.IndexOf('#');
            string trailingComment = string.Empty;
            if (hash >= 0)
            {
                trailingComment = body[(hash + 1)..].Trim();
                body = body[..hash];
            }
            body = body.Trim();
            if (body.Length == 0)
                continue;

            int arrow = body.IndexOf("->", StringComparison.Ordinal);
            if (arrow < 0)
                continue;

            string old = body[..arrow].Trim();
            string @new = body[(arrow + 2)..].Trim();
            if (old.Length == 0 || @new.Length == 0)
                continue;

            // A structural-adaptation marker's RHS is prose (contains a space and lowercase words
            // like "property"/"payload"/"argument"), not a code token. Those are documented shape
            // changes, not token renames; the tool reports them transparently and excludes the
            // matching source assertion from the strict literal/structure diff.
            bool structural = IsProse(@new) || IsProse(old);

            renames.Add(new RenameEntry(old, @new, structural));
        }

        if (renames.Count == 0)
            throw new InvalidOperationException("PARITY.md: no rename-map entries found in the ```parity-rename-map block.");
        return renames;
    }

    private static bool IsProse(string s)
    {
        // Code tokens here are identifiers, dotted names, or method chains with optional
        // parens/args — they contain no spaces except inside "(...)". Prose markers contain a
        // top-level space (outside any parentheses).
        int depth = 0;
        foreach (char c in s)
        {
            if (c == '(') depth++;
            else if (c == ')') { if (depth > 0) depth--; }
            else if (c == ' ' && depth == 0) return true;
        }
        return false;
    }
}
