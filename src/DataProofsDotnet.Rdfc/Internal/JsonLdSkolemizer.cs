using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DataProofsDotnet.Rdfc.Internal;

/// <summary>
/// Compact-JSON-LD blank-node skolemization for the <c>bbs-2023</c> group partition (FR-12,
/// spec §3.4.16 <c>canonicalizeAndGroup</c> / DI-ECDSA skolemize primitives).
/// </summary>
/// <remarks>
/// <para>
/// To split a document's canonical N-Quads into pointer-addressed groups, the spec replaces
/// blank nodes with stable <c>urn:bnid:_:b*</c> URIs <em>before</em> selecting sub-documents,
/// so a sub-document's RDF nodes keep the identity they had in the whole document and its
/// canonical N-Quads are an exact subset of the whole. This skolemizer assigns each
/// <c>@id</c>-less JSON-LD node object a deterministic <c>urn:bnid:_:b{n}</c> identifier in
/// document order; <see cref="Deskolemize"/> reverses it on the resulting N-Quads.
/// </para>
/// <para>
/// The assignment is exact for tree-structured documents (the VC shapes <c>bbs-2023</c>
/// targets), where every blank node is reached by exactly one path. Pure functions.
/// </para>
/// </remarks>
internal static class JsonLdSkolemizer
{
    /// <summary>The URN scheme the skolemizer maps blank nodes onto.</summary>
    public const string UrnPrefix = "urn:bnid:";

    /// <summary>
    /// Returns a copy of <paramref name="document"/> with every <c>@id</c>-less node object
    /// assigned a deterministic <c>urn:bnid:_:b{n}</c> identifier (document-order counter).
    /// </summary>
    public static JsonObject Skolemize(JsonElement document)
    {
        if (document.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("Skolemization requires a JSON object document.", nameof(document));
        }

        var root = (JsonObject)JsonNode.Parse(document.GetRawText())!;
        var counter = 0;
        SkolemizeNode(root, ref counter, isRoot: true);
        return root;
    }

    private static void SkolemizeNode(JsonNode? node, ref int counter, bool isRoot)
    {
        switch (node)
        {
            case JsonObject obj:
                if (!isRoot && IsNodeObject(obj) && !HasId(obj))
                {
                    obj["@id"] = UrnPrefix + "_:b" + counter.ToString(CultureInfo.InvariantCulture);
                    counter++;
                }

                foreach (var property in obj.ToArray())
                {
                    if (property.Key is "@context" or "@id" or "id" or "@type" or "type")
                    {
                        continue;
                    }

                    SkolemizeNode(property.Value, ref counter, isRoot: false);
                }

                break;

            case JsonArray array:
                foreach (var element in array)
                {
                    SkolemizeNode(element, ref counter, isRoot: false);
                }

                break;
        }
    }

    /// <summary>
    /// Reverses skolemization on canonical N-Quad lines: rewrites every
    /// <c>&lt;urn:bnid:_:b*&gt;</c> URI node back to the blank node <c>_:b*</c>.
    /// </summary>
    public static IReadOnlyList<string> Deskolemize(IEnumerable<string> nquads)
    {
        var deskolemized = new List<string>();
        foreach (var line in nquads)
        {
            deskolemized.Add(Rewrite(line));
        }

        return deskolemized;
    }

    // A node object carries graph structure (it is not a JSON-LD value/list/set wrapper).
    private static bool IsNodeObject(JsonObject obj)
        => !obj.ContainsKey("@value") && !obj.ContainsKey("@list") && !obj.ContainsKey("@set");

    private static bool HasId(JsonObject obj)
        => obj.ContainsKey("@id") || obj.ContainsKey("id");

    // Replaces "<urn:bnid:_:bN>" tokens with "_:bN" wherever they appear in an N-Quad line.
    private static string Rewrite(string line)
    {
        var marker = "<" + UrnPrefix + "_:";
        var result = line;
        int index;
        while ((index = result.IndexOf(marker, StringComparison.Ordinal)) >= 0)
        {
            var close = result.IndexOf('>', index);
            if (close < 0)
            {
                break;
            }

            var bnode = result.Substring(index + marker.Length - "_:".Length, close - (index + marker.Length - "_:".Length));
            result = result[..index] + bnode + result[(close + 1)..];
        }

        return result;
    }
}
