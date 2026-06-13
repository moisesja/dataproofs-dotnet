namespace DataProofsDotnet.Tools.ParityDiff;

/// <summary>
/// Applies PARITY.md's recorded rename map to a (whitespace-collapsed) assertion statement so the
/// didcomm source and the ported file normalize to a common identifier vocabulary before the diff.
///
/// Two entry kinds (see <see cref="ParityManifest"/>):
///   * Token renames (RHS is a code fragment) are applied as ordered textual substitutions,
///     longest-LHS first so a longer mapping (e.g. <c>DidComm.Crypto.Kdf</c>) wins over a shorter
///     prefix (<c>DidComm.Crypto</c>).
///   * Structural-adaptation markers (RHS is prose) are NOT substituted — they document a sanctioned
///     shape change. Source assertions whose text mentions the marker's LHS code token, and the
///     ported assertions that replace them, are detected here and set aside by the diff so the
///     strict comparison covers only assertions that must remain byte-for-byte parity.
/// </summary>
internal sealed class RenameNormalizer
{
    private readonly List<(string Old, string New)> _tokenRenames;
    private readonly List<string> _structuralSourceTokens; // code tokens that mark an adapted SOURCE assertion
    private readonly List<string> _structuralPortedHints;   // code tokens/literals in the adapted PORTED assertion

    public RenameNormalizer(IReadOnlyList<RenameEntry> renames)
    {
        _tokenRenames = renames
            .Where(r => !r.StructuralAdaptation)
            .Select(r => (r.Old, r.New))
            .OrderByDescending(r => r.Old.Length)
            .ToList();

        _structuralSourceTokens = new List<string>();
        _structuralPortedHints = new List<string>();
        foreach (var r in renames.Where(r => r.StructuralAdaptation))
        {
            string srcToken = LeadingCodeToken(r.Old);
            if (srcToken.Length > 0)
                _structuralSourceTokens.Add(srcToken);

            // The ported side of a payload-property adaptation reads e.g. GetProperty("id");
            // capture the quoted hint ("id"/"from") so the matching ported assertion is recognized.
            foreach (var lit in QuotedLiterals(r.New))
                _structuralPortedHints.Add($"GetProperty(\"{lit}\")");
        }
    }

    /// <summary>Applies the ordered token renames to an assertion statement.</summary>
    public string Normalize(string assertion)
    {
        string s = assertion;
        foreach (var (old, @new) in _tokenRenames)
            s = s.Replace(old, @new, StringComparison.Ordinal);
        return s;
    }

    /// <summary>
    /// True if this SOURCE assertion is a sanctioned structural adaptation (its expression is one
    /// the PARITY.md rename map marks as reshaped, e.g. <c>result.Message.Id</c>).
    /// </summary>
    public bool IsStructurallyAdapted(string sourceAssertion) =>
        _structuralSourceTokens.Any(t => sourceAssertion.Contains(t, StringComparison.Ordinal));

    /// <summary>
    /// True if this PORTED assertion is the reshaped counterpart of a sanctioned adaptation (e.g. it
    /// reads <c>GetProperty("id")</c> / <c>GetProperty("from")</c> from the parsed payload JSON).
    /// </summary>
    public bool IsPortedAdaptation(string portedAssertion) =>
        _structuralPortedHints.Any(h => portedAssertion.Contains(h, StringComparison.Ordinal));

    // The meaningful code token at the start of a structural LHS such as
    // "signer.PrivateJwk (as JwsBuilder argument)" -> "signer.PrivateJwk".
    private static string LeadingCodeToken(string s)
    {
        int space = s.IndexOf(' ');
        return (space < 0 ? s : s[..space]).Trim();
    }

    private static IEnumerable<string> QuotedLiterals(string s)
    {
        int i = 0;
        while (i < s.Length)
        {
            int open = s.IndexOf('"', i);
            if (open < 0) yield break;
            int close = s.IndexOf('"', open + 1);
            if (close < 0) yield break;
            yield return s.Substring(open + 1, close - open - 1);
            i = close + 1;
        }
    }
}
