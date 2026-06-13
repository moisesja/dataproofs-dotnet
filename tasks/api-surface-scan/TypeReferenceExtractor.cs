namespace DataProofsDotnet.Tools.ApiSurfaceScan;

/// <summary>
/// Tokenizes a single PublicAPI.*.txt declaration line and extracts every fully-qualified type
/// reference it carries, so the allowlist (AC-7) can be enforced over the type names rather than
/// over member names.
///
/// The PublicAPI line format (emitted by Microsoft.CodeAnalysis.PublicApiAnalyzers) puts type
/// references in three positions:
///   1. the declaring-type prefix of a member ("Ns.OuterType.Member.get -> …");
///   2. parameter types inside "( … )";
///   3. the return type after " -> ".
/// plus base-type/interface lines, generics &lt;…&gt;, arrays [], tuples ( … ), C# keyword
/// aliases (void/bool/int/string/byte/object/…), and the !/? nullability suffixes.
///
/// Strategy: this extractor does NOT try to fully parse C#. Instead it walks the line, splits on
/// the structural punctuation that separates type tokens (whitespace, &lt; &gt; [ ] ( ) , and the
/// "->" arrow), strips !/? suffixes and ref/out/params/this/static/const/readonly/override/abstract
/// /virtual/sealed/operator/implicit/explicit keywords, maps C# keyword aliases to their System
/// types, and emits every token that LOOKS like a type reference: a dotted fully-qualified name
/// (contains '.') OR a mapped keyword alias. Bare single-identifier tokens that are not keyword
/// aliases are member names / parameter names / generic type-parameter names and are skipped —
/// they cannot name a forbidden backend type, because any backend type appears fully qualified in
/// the PublicAPI format. This is conservative in the safe direction: a forbidden type can only be
/// written as a dotted FQN here, and every dotted FQN is checked.
/// </summary>
internal static class TypeReferenceExtractor
{
    // C# keyword aliases -> their System type FQN. Mapped before matching so the allowlist only
    // needs to list the System types (AC-7: "C# keyword aliases mapped to their System types").
    private static readonly Dictionary<string, string> KeywordAliases = new(StringComparer.Ordinal)
    {
        ["void"] = "System.Void",
        ["bool"] = "System.Boolean",
        ["byte"] = "System.Byte",
        ["sbyte"] = "System.SByte",
        ["char"] = "System.Char",
        ["short"] = "System.Int16",
        ["ushort"] = "System.UInt16",
        ["int"] = "System.Int32",
        ["uint"] = "System.UInt32",
        ["long"] = "System.Int64",
        ["ulong"] = "System.UInt64",
        ["nint"] = "System.IntPtr",
        ["nuint"] = "System.UIntPtr",
        ["float"] = "System.Single",
        ["double"] = "System.Double",
        ["decimal"] = "System.Decimal",
        ["string"] = "System.String",
        ["object"] = "System.Object",
    };

    // Declaration-leading keywords and modifiers that are not type references.
    private static readonly HashSet<string> Noise = new(StringComparer.Ordinal)
    {
        "const", "static", "readonly", "override", "abstract", "virtual", "sealed", "extern",
        "ref", "out", "in", "params", "this", "operator", "implicit", "explicit", "new",
        "get", "set", "init", "add", "remove", "default", "null", "true", "false", "enum",
        "class", "struct", "interface", "delegate", "event",
    };

    /// <summary>
    /// Extracts the distinct type references from one PublicAPI line. Lines that are blank,
    /// comments, or the "#nullable enable" header yield nothing.
    /// </summary>
    public static IReadOnlyList<string> Extract(string line)
    {
        var results = new List<string>();
        if (string.IsNullOrWhiteSpace(line))
            return results;

        var trimmed = line.Trim();
        if (trimmed.StartsWith('#'))
            return results;

        // Drop a const initializer ("= \"value\"" / "= -8") — the literal is not a type and may
        // contain '.' (e.g. a version string) that would masquerade as an FQN.
        int eq = IndexOfTopLevelEquals(trimmed);
        string declaration;
        string returnPart = string.Empty;
        if (eq >= 0)
        {
            declaration = trimmed[..eq];
            // After "= literal" an enum/const line has no "-> type" worth scanning for the literal,
            // but a regular member does: "const X = "v" -> string!" — keep the part after "->".
            int arrowAfterEq = trimmed.IndexOf("->", eq, StringComparison.Ordinal);
            if (arrowAfterEq >= 0)
                returnPart = trimmed[(arrowAfterEq + 2)..];
        }
        else
        {
            int arrow = trimmed.IndexOf("->", StringComparison.Ordinal);
            if (arrow >= 0)
            {
                declaration = trimmed[..arrow];
                returnPart = trimmed[(arrow + 2)..];
            }
            else
            {
                declaration = trimmed;
            }
        }

        ExtractFromSegment(declaration, results);
        ExtractFromSegment(returnPart, results);
        return results;
    }

    private static int IndexOfTopLevelEquals(string s)
    {
        // The only '=' that introduces a literal in this format sits outside <…> and (…) and is
        // surrounded by spaces (" = "). Enum members and consts use it; nullable-suffix '?' and
        // default-parameter "= default(…)" also use it, which we still want to drop.
        int depthAngle = 0, depthParen = 0;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            switch (c)
            {
                case '<': depthAngle++; break;
                case '>': if (depthAngle > 0) depthAngle--; break;
                case '(': depthParen++; break;
                case ')': if (depthParen > 0) depthParen--; break;
                case '=' when depthAngle == 0 && depthParen == 0
                              && i > 0 && s[i - 1] == ' '
                              && i + 1 < s.Length && s[i + 1] == ' ':
                    return i;
            }
        }
        return -1;
    }

    private static void ExtractFromSegment(string segment, List<string> sink)
    {
        if (string.IsNullOrWhiteSpace(segment))
            return;

        // Split into candidate tokens on the structural punctuation that delimits type tokens.
        // Keep dots inside a token (they form the FQN); everything else is a separator.
        var token = new System.Text.StringBuilder();
        foreach (char c in segment)
        {
            if (IsTokenChar(c))
            {
                token.Append(c);
            }
            else
            {
                Flush(token, sink);
            }
        }
        Flush(token, sink);
    }

    private static bool IsTokenChar(char c) =>
        char.IsLetterOrDigit(c) || c == '.' || c == '_';

    private static void Flush(System.Text.StringBuilder token, List<string> sink)
    {
        if (token.Length == 0)
            return;
        string raw = token.ToString();
        token.Clear();

        // Strip a trailing generic arity left by "Foo`1" style names (PublicAPI uses <…> instead,
        // but be defensive). Strip nothing else: !/? were already removed as non-token chars.
        int backtick = raw.IndexOf('`');
        if (backtick >= 0)
            raw = raw[..backtick];

        if (raw.Length == 0)
            return;

        if (Noise.Contains(raw))
            return;

        if (KeywordAliases.TryGetValue(raw, out var mapped))
        {
            sink.Add(mapped);
            return;
        }

        // Only dotted, fully-qualified names are type references in this position. A bare
        // identifier is a member/parameter/type-parameter name (e.g. "document", "T", "get").
        if (raw.Contains('.'))
        {
            // Trim a trailing '.' that can appear when a member access was split oddly.
            string fqn = raw.TrimEnd('.');
            if (fqn.Length > 0 && fqn.Contains('.'))
                sink.Add(fqn);
        }
    }
}
