using System.Text;
using NetCid;

namespace DataProofsDotnet.Rdfc.Internal;

/// <summary>
/// Blank-node relabeling for the <c>bbs-2023</c> selective-disclosure lifecycle (FR-12):
/// the HMAC-shuffled <c>c14n*</c> → <c>b*</c> label maps and the N-Quads relabeling those
/// maps drive.
/// </summary>
/// <remarks>
/// <para>
/// After RDFC-1.0 the canonical blank-node labels (<c>c14n0</c>, <c>c14n1</c>, …) leak
/// document structure. <c>bbs-2023</c> replaces them with labels derived from an HMAC of
/// the canonical label, keyed by a per-credential secret, then assigns sequential
/// <c>b*</c> labels by the sorted order of those HMAC digests (spec §3.2.1
/// <c>createShuffledIdLabelMapFunction</c>). The HMAC is composed over NetCrypto's SHA-256
/// (<see cref="HmacSha256"/>); base64url-no-pad encoding routes through NetCid. No
/// <c>System.Security.Cryptography</c> primitive is used.
/// </para>
/// <para>
/// Labels are found and replaced as <em>terms</em> (<see cref="RewriteTerms"/>), never as text: a
/// literal can contain <c>_:b0</c> or <c>&lt;urn:bnid:_:b0&gt;</c>, and rewriting it let two
/// different literal values reach the signature as the same message (adversarial review).
/// </para>
/// <para>Pure functions.</para>
/// </remarks>
internal static class BlankNodeLabels
{
    /// <summary>
    /// Builds the spec's shuffled HMAC label map (bbs-2023 <c>createShuffledIdLabelMapFunction</c>):
    /// each canonical blank-node label (without the <c>_:</c> prefix, e.g. <c>c14n0</c>) maps to a
    /// sequential <c>b*</c> label assigned by the sorted order of the labels' HMAC digests. The
    /// digest is over the canonical label, so two implementations canonicalizing the same dataset
    /// derive the same labels from the same key.
    /// </summary>
    public static IReadOnlyDictionary<string, string> CreateShuffledIdLabelMap(
        IEnumerable<string> canonicalLabels, ReadOnlySpan<byte> hmacKey)
    {
        var keyBytes = hmacKey.ToArray();
        var labels = canonicalLabels.Distinct(StringComparer.Ordinal).ToList();

        var digests = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var label in labels)
        {
            var hmac = HmacSha256.Compute(keyBytes, Encoding.UTF8.GetBytes(label));
            // "u" + base64url-no-pad (the spec's b64urlDigest), via NetCid.
            digests[label] = Multibase.Encode(hmac, MultibaseEncoding.Base64Url);
        }

        // Sort labels by their HMAC digest; assign b0, b1, … in that order.
        var sorted = labels.OrderBy(label => digests[label], StringComparer.Ordinal).ToList();
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < sorted.Count; i++)
        {
            map[sorted[i]] = "b" + i.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        return map;
    }

    /// <summary>
    /// Relabels every blank node in <paramref name="canonicalNQuads"/> using
    /// <paramref name="labelMap"/> (canonical label → new label, both without <c>_:</c>),
    /// then returns the relabeled lines sorted in code-point order (the spec's
    /// <c>labelReplacementCanonicalize</c> output ordering).
    /// </summary>
    public static IReadOnlyList<string> RelabelAndSort(
        IEnumerable<string> canonicalNQuads, IReadOnlyDictionary<string, string> labelMap)
    {
        var relabeled = new List<string>();
        foreach (var nquad in canonicalNQuads)
        {
            relabeled.Add(Relabel(nquad, labelMap));
        }

        relabeled.Sort(StringComparer.Ordinal);
        return relabeled;
    }

    /// <summary>The distinct blank-node labels (without <c>_:</c>) of the given N-Quad lines, in first-seen order.</summary>
    public static IReadOnlyList<string> LabelsOf(IEnumerable<string> nquads)
    {
        var labels = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var nquad in nquads)
        {
            RewriteTerms(nquad, blankNode: label =>
            {
                if (seen.Add(label))
                {
                    labels.Add(label);
                }

                return "_:" + label;
            });
        }

        return labels;
    }

    /// <summary>Splits canonical N-Quads text into individual newline-terminated lines.</summary>
    public static IReadOnlyList<string> SplitLines(string canonicalNQuads)
    {
        ArgumentNullException.ThrowIfNull(canonicalNQuads);
        var lines = new List<string>();
        var start = 0;
        for (var i = 0; i < canonicalNQuads.Length; i++)
        {
            if (canonicalNQuads[i] == '\n')
            {
                lines.Add(canonicalNQuads[start..(i + 1)]);
                start = i + 1;
            }
        }

        return lines;
    }

    /// <summary>
    /// Rewrites the blank-node and IRI terms of one canonical N-Quad line, copying every literal
    /// whole. <paramref name="blankNode"/> gets a label without <c>_:</c>, <paramref name="iri"/> an
    /// IRI without its angle brackets; each returns the term's replacement text.
    /// </summary>
    public static string RewriteTerms(string nquad, Func<string, string>? blankNode = null, Func<string, string>? iri = null)
    {
        var result = new StringBuilder(nquad.Length);
        var i = 0;
        while (i < nquad.Length)
        {
            if (nquad[i] == '"')
            {
                // A literal ends at the first quote not escaped by a backslash.
                var end = i + 1;
                while (end < nquad.Length && nquad[end] != '"')
                {
                    end += nquad[end] == '\\' ? 2 : 1;
                }

                end = Math.Min(end + 1, nquad.Length);
                result.Append(nquad, i, end - i);
                i = end;
            }
            else if (nquad[i] == '<' && nquad.IndexOf('>', i) is var close and > 0)
            {
                var content = nquad.Substring(i + 1, close - i - 1);
                result.Append(iri is null ? "<" + content + ">" : iri(content));
                i = close + 1;
            }
            else if (nquad[i] == '_' && i + 1 < nquad.Length && nquad[i + 1] == ':')
            {
                var end = i + 2;
                while (end < nquad.Length && char.IsAsciiLetterOrDigit(nquad[end]))
                {
                    end++;
                }

                var label = nquad.Substring(i + 2, end - i - 2);
                result.Append(blankNode is null ? "_:" + label : blankNode(label));
                i = end;
            }
            else
            {
                result.Append(nquad[i]);
                i++;
            }
        }

        return result.ToString();
    }

    private static string Relabel(string nquad, IReadOnlyDictionary<string, string> labelMap)
        => RewriteTerms(nquad, blankNode: label =>
            labelMap.TryGetValue(label, out var replacement) ? "_:" + replacement : "_:" + label);
}
