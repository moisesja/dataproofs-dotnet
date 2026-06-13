using System.Text;
using System.Text.RegularExpressions;

namespace DataProofsDotnet.Tools.ParityDiff;

/// <summary>
/// Extracts the assertion statements from a C# test file's source text. An assertion statement is
/// a logical statement (terminated by ';' at brace/paren depth 0) that invokes the test
/// framework's assertion API — FluentAssertions <c>.Should()</c> chains or xunit <c>Assert.*</c>
/// calls. FluentAssertions chains routinely span several physical lines (a <c>.WithMessage(...)</c>
/// or <c>because:</c> on the next line), so statements are reassembled across line breaks before
/// the per-statement filter is applied.
/// </summary>
internal static class AssertionExtractor
{
    private static readonly Regex AssertionMarker =
        new(@"\.Should\(\)|(^|[^\w.])Assert\.", RegexOptions.Compiled);

    // Matches a method declaration's name: "public void Foo(" / "public async Task Foo<T>(".
    private static readonly Regex MethodNameRegex =
        new(@"\b(?:public|private|protected|internal)\b[^;{=]*?\b([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(",
            RegexOptions.Compiled);

    /// <summary>One assertion statement plus the name of the test method that contains it.</summary>
    public readonly record struct TaggedAssertion(string Statement, string Method);

    /// <summary>Returns the ordered list of normalized assertion statements in the file text.</summary>
    public static List<string> Extract(string sourceText) =>
        ExtractTagged(sourceText).Select(t => t.Statement).ToList();

    /// <summary>
    /// Returns each assertion statement tagged with the enclosing method name, so callers can drop
    /// assertions from PARITY.md-sanctioned omitted source tests.
    /// </summary>
    public static List<TaggedAssertion> ExtractTagged(string sourceText)
    {
        var statements = SplitTopLevelStatements(sourceText);
        var result = new List<TaggedAssertion>();
        string currentMethod = string.Empty;

        foreach (var stmt in statements)
        {
            // A statement chunk begins with everything since the previous ';'; a method header
            // (e.g. "}\n\n[Fact]\npublic void Foo()") is captured in the chunk preceding the
            // method's first statement. Update the current method from the last header seen here.
            foreach (Match m in MethodNameRegex.Matches(stmt))
                currentMethod = m.Groups[1].Value;

            if (AssertionMarker.IsMatch(stmt))
                result.Add(new TaggedAssertion(CollapseWhitespace(stmt), currentMethod));
        }
        return result;
    }

    /// <summary>
    /// Splits a C# file into statements at ';' tokens that sit outside strings, chars, comments,
    /// and round/square bracketing. Curly-brace depth is deliberately NOT a guard: a ';' inside a
    /// method or class body still terminates a statement, while a ';' inside <c>for ( ; ; )</c>
    /// sits at round-paren depth &gt; 0 and is correctly skipped. This is intentionally coarse — it
    /// only needs to group multi-line FluentAssertions chains into one unit and is robust to the
    /// test-file constructs in the parity suite (verbatim strings, lambdas, attribute brackets).
    /// </summary>
    private static List<string> SplitTopLevelStatements(string text)
    {
        var statements = new List<string>();
        var current = new StringBuilder();
        int round = 0, square = 0;
        bool inLineComment = false, inBlockComment = false;
        bool inString = false, inVerbatim = false, inChar = false, inInterp = false;

        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            char next = i + 1 < text.Length ? text[i + 1] : '\0';

            // Comments.
            if (inLineComment)
            {
                if (c == '\n') inLineComment = false;
                continue;
            }
            if (inBlockComment)
            {
                if (c == '*' && next == '/') { inBlockComment = false; i++; }
                continue;
            }

            // Strings / chars.
            if (inString)
            {
                current.Append(c);
                if (inVerbatim)
                {
                    if (c == '"' && next == '"') { current.Append(next); i++; }
                    else if (c == '"') { inString = false; inVerbatim = false; }
                }
                else
                {
                    if (c == '\\' && next != '\0') { current.Append(next); i++; }
                    else if (c == '"') inString = false;
                }
                continue;
            }
            if (inChar)
            {
                current.Append(c);
                if (c == '\\' && next != '\0') { current.Append(next); i++; }
                else if (c == '\'') inChar = false;
                continue;
            }

            // Comment starts.
            if (c == '/' && next == '/') { inLineComment = true; i++; continue; }
            if (c == '/' && next == '*') { inBlockComment = true; i++; continue; }

            // String / char starts (handle @" and $" and $@").
            if (c == '@' && next == '"') { current.Append(c); current.Append(next); inString = true; inVerbatim = true; i++; continue; }
            if (c == '$' && next == '@' && i + 2 < text.Length && text[i + 2] == '"')
            { current.Append(c); current.Append(next); current.Append(text[i + 2]); inString = true; inVerbatim = true; inInterp = true; i += 2; continue; }
            if (c == '$' && next == '"') { current.Append(c); current.Append(next); inString = true; i++; continue; }
            if (c == '"') { current.Append(c); inString = true; continue; }
            if (c == '\'') { current.Append(c); inChar = true; continue; }

            switch (c)
            {
                case '(': round++; break;
                case ')': if (round > 0) round--; break;
                case '[': square++; break;
                case ']': if (square > 0) square--; break;
            }

            current.Append(c);

            if (c == ';' && round == 0 && square == 0)
            {
                statements.Add(current.ToString());
                current.Clear();
            }
        }

        _ = inInterp; // interpolation depth is not tracked beyond the opening quote; adequate here.
        if (current.ToString().Trim().Length > 0)
            statements.Add(current.ToString());
        return statements;
    }

    private static string CollapseWhitespace(string s)
    {
        var sb = new StringBuilder(s.Length);
        bool lastSpace = false;
        foreach (char c in s)
        {
            if (char.IsWhiteSpace(c))
            {
                if (!lastSpace) { sb.Append(' '); lastSpace = true; }
            }
            else
            {
                sb.Append(c);
                lastSpace = false;
            }
        }
        return sb.ToString().Trim();
    }
}
