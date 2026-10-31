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

    // Generated skolem labels carry a per-process random part so they cannot collide with a blank
    // node identifier the document spells out itself (which is preserved, as the reference does).
    private static readonly string Run = Guid.NewGuid().ToString("N");

    /// <summary>
    /// Returns a copy of <paramref name="document"/> in which every node object has an IRI: an
    /// <c>@id</c>-less one gets <c>urn:bnid:_:b{n}x{run}</c> (document-order counter), and one whose
    /// <c>@id</c> or <c>id</c> is a blank node identifier <c>_:x</c> gets <c>urn:bnid:_:x</c>, so a
    /// shared identifier keeps naming one node.
    /// </summary>
    public static JsonObject Skolemize(JsonElement document)
    {
        if (document.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("Skolemization requires a JSON object document.", nameof(document));
        }

        var root = (JsonObject)JsonNode.Parse(document.GetRawText())!;
        var counter = 0;
        SkolemizeNode(root, ref counter);
        return root;
    }

    private static void SkolemizeNode(JsonNode? node, ref int counter)
    {
        switch (node)
        {
            case JsonObject obj:
                // Assign a stable id to every blank node object (including the top-level node,
                // which is itself a blank node when it carries no @id) so selections inherit it.
                if (IsNodeObject(obj))
                {
                    var idKey = obj.ContainsKey("@id") ? "@id" : obj.ContainsKey("id") ? "id" : null;
                    if (idKey is null)
                    {
                        obj["@id"] = UrnPrefix + "_:b" + counter.ToString(CultureInfo.InvariantCulture) + "x" + Run;
                        counter++;
                    }
                    else if (obj[idKey] is JsonValue value && value.TryGetValue<string>(out var id)
                        && id.StartsWith("_:", StringComparison.Ordinal))
                    {
                        obj[idKey] = UrnPrefix + id;
                    }
                }

                foreach (var property in obj.ToArray())
                {
                    if (property.Key is "@context" or "@id" or "id" or "@type" or "type")
                    {
                        continue;
                    }

                    SkolemizeNode(property.Value, ref counter);
                }

                break;

            case JsonArray array:
                foreach (var element in array)
                {
                    SkolemizeNode(element, ref counter);
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

    // Replaces each "<urn:bnid:_:bN>" IRI term with the blank node "_:bN". Literals are left whole:
    // one may contain that text, which is data, not a skolem id (adversarial review).
    private static string Rewrite(string line)
        => BlankNodeLabels.RewriteTerms(line, iri: iri =>
            iri.StartsWith(UrnPrefix + "_:", StringComparison.Ordinal) ? iri[UrnPrefix.Length..] : "<" + iri + ">");
}
