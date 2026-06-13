using System.Text;
using System.Text.RegularExpressions;
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
/// <para>Pure functions; the regexes are compiled once and stateless.</para>
/// </remarks>
internal static class BlankNodeLabels
{
    // Matches every blank-node label token "_:<name>" in an N-Quad line.
    private static readonly Regex BlankNodePattern = new(@"_:([A-Za-z0-9]+)", RegexOptions.Compiled);

    /// <summary>
    /// Builds the HMAC-shuffled label map: each distinct canonical blank-node label
    /// (without the <c>_:</c> prefix, e.g. <c>c14n0</c>) maps to a sequential <c>b*</c>
    /// label assigned by the sorted order of the labels' HMAC digests (spec §3.2.1).
    /// </summary>
    public static IReadOnlyDictionary<string, string> CreateHmacIdLabelMap(
        IEnumerable<string> canonicalNQuads, ReadOnlySpan<byte> hmacKey)
    {
        var keyBytes = hmacKey.ToArray();

        // Collect distinct canonical labels in first-seen order, with their HMAC digests.
        var labels = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var nquad in canonicalNQuads)
        {
            foreach (Match match in BlankNodePattern.Matches(nquad))
            {
                var label = match.Groups[1].Value;
                if (seen.Add(label))
                {
                    labels.Add(label);
                }
            }
        }

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

    private static string Relabel(string nquad, IReadOnlyDictionary<string, string> labelMap)
        => BlankNodePattern.Replace(nquad, match =>
        {
            var label = match.Groups[1].Value;
            return labelMap.TryGetValue(label, out var replacement) ? "_:" + replacement : match.Value;
        });
}
