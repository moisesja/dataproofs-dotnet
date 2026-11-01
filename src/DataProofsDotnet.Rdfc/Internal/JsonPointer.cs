using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DataProofsDotnet.Rdfc.Internal;

/// <summary>
/// RFC 6901 JSON Pointer evaluation and JSON-LD sub-document selection for the
/// <c>bbs-2023</c> selective-disclosure lifecycle (FR-12).
/// </summary>
/// <remarks>
/// <para>
/// <c>bbs-2023</c> partitions a document into mandatory and selectively-disclosed groups
/// addressed by arrays of JSON Pointers. <see cref="SelectJsonLd"/> implements the spec's
/// <c>selectJsonLd</c> primitive (shared with <c>ecdsa-sd-2023</c>): it builds the minimal
/// sub-document containing every value addressed by a pointer, preserving the document's
/// <c>@context</c> and any type members on the path so the result is still JSON-LD
/// processable.
/// </para>
/// <para>Pure functions; no shared mutable state.</para>
/// </remarks>
internal static class JsonPointer
{
    /// <summary>
    /// Parses an RFC 6901 JSON Pointer into its reference tokens (with <c>~1</c>→<c>/</c>
    /// and <c>~0</c>→<c>~</c> unescaping). The empty pointer yields no tokens.
    /// </summary>
    public static IReadOnlyList<string> Parse(string pointer)
    {
        ArgumentNullException.ThrowIfNull(pointer);
        if (pointer.Length == 0)
        {
            return [];
        }

        if (pointer[0] != '/')
        {
            throw new ArgumentException($"JSON Pointer '{pointer}' must start with '/'.", nameof(pointer));
        }

        var rawTokens = pointer.Split('/');
        var tokens = new string[rawTokens.Length - 1];
        for (var i = 1; i < rawTokens.Length; i++)
        {
            tokens[i - 1] = rawTokens[i].Replace("~1", "/", StringComparison.Ordinal).Replace("~0", "~", StringComparison.Ordinal);
        }

        return tokens;
    }

    /// <summary>Whether <paramref name="pointer"/> addresses a value in <paramref name="document"/>.</summary>
    public static bool Resolves(JsonNode document, string pointer)
        => Parse(pointer).Aggregate((JsonNode?)document, Step) is not null;

    /// <summary>
    /// Whether <paramref name="pointer"/> ends inside a value object that holds more than its
    /// <c>@value</c>. Alone, its <c>@language</c> or <c>@direction</c> is no statement, so selecting it
    /// selects nothing, and nothing shows that it did. Alone, its <c>@value</c> is another literal,
    /// which a statement beside it can match. Only the whole object selects the value.
    /// </summary>
    public static bool SelectsPartOfAValue(JsonNode document, string pointer)
        => Parse(pointer).SkipLast(1).Aggregate((JsonNode?)document, Step) is JsonObject { Count: > 1 } value
            && value.ContainsKey("@value");

    /// <summary>
    /// Builds the JSON-LD sub-document containing only the values addressed by
    /// <paramref name="pointers"/>, copying the document's <c>@context</c> and the
    /// <c>type</c>/<c>@type</c> members along each addressed path (the spec's
    /// <c>selectJsonLd</c> algorithm). Returns <c>null</c> when no pointer selects anything.
    /// </summary>
    public static JsonNode? SelectJsonLd(JsonElement document, IReadOnlyList<string> pointers)
    {
        ArgumentNullException.ThrowIfNull(pointers);
        if (document.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("selectJsonLd requires a JSON object document.", nameof(document));
        }

        if (pointers.Count == 0)
        {
            return null;
        }

        var source = JsonNode.Parse(document.GetRawText())!;
        JsonNode? selection = null;
        // Only arrays built while walking pointers contain selection holes. Deep-copied arrays
        // (notably inside @json literals) contain actual data, including meaningful nulls.
        var sparseArrays = new Dictionary<JsonArray, HashSet<int>>(ReferenceEqualityComparer.Instance);

        foreach (var pointer in pointers)
        {
            var tokens = Parse(pointer);
            if (tokens.Count == 0)
            {
                // The empty pointer addresses the whole document (RFC 6901; the spec's selectJsonLd).
                return JsonNode.Parse(document.GetRawText());
            }

            selection = SelectPath(source, tokens, selection, sparseArrays);
        }

        if (selection is JsonObject selectionObject)
        {
            // Carry @context verbatim so the selection re-expands under the same vocabulary.
            if (document.TryGetProperty("@context", out var context))
            {
                selectionObject["@context"] = JsonNode.Parse(context.GetRawText());
            }
        }

        // Densify only the tracked sparse arrays (selectJsonLd step 6), preserving every
        // explicitly populated slot. Process backwards so removing a hole cannot shift later indexes.
        foreach (var (array, populated) in sparseArrays)
        {
            for (var i = array.Count - 1; i >= 0; i--)
            {
                if (!populated.Contains(i)) array.RemoveAt(i);
            }
        }
        return selection;
    }

    /// <summary>
    /// The selection algorithm assumes only a root context. Check syntactically, conservatively
    /// including literal data, without guessing which objects a JSON-LD processor treats as literals.
    /// Context definitions themselves may contain scoped contexts and are left to the processor.
    /// </summary>
    public static bool HasNestedContext(JsonElement document, bool root = true)
    {
        switch (document.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in document.EnumerateObject())
                {
                    if (property.NameEquals("@context"))
                    {
                        if (!root) return true;
                    }
                    else if (HasNestedContext(property.Value, false)) return true;
                }
                break;
            case JsonValueKind.Array:
                foreach (var element in document.EnumerateArray())
                {
                    if (HasNestedContext(element, false)) return true;
                }
                break;
        }
        return false;
    }

    // Walks one pointer path against the source, materializing the addressed value into the
    // accumulating selection (creating intermediate containers and copying type members).
    private static JsonNode? SelectPath(JsonNode source, IReadOnlyList<string> tokens, JsonNode? selection,
        Dictionary<JsonArray, HashSet<int>> sparseArrays)
    {
        var sourceCursor = source;

        // The path's value must exist in the source. A pointer addressing nothing is an error, as in
        // the spec's selectJsonLd: silently skipping it let an issuer's mandatory pointer, or a
        // holder's selective one, select nothing without anyone noticing (PR #42 review).
        foreach (var token in tokens)
        {
            sourceCursor = Step(sourceCursor, token);
            if (sourceCursor is null)
            {
                throw new ArgumentException("A JSON pointer does not match the document.", nameof(tokens));
            }
        }

        // Re-walk, mirroring the structure into the selection and copying type members.
        selection ??= NewContainerLike(source, sparseArrays);
        var selCursor = selection;
        var srcCursor = source;

        for (var i = 0; i < tokens.Count; i++)
        {
            var token = tokens[i];
            srcCursor = Step(srcCursor, token)!;

            CopyTypeMembers(GetParentObjectBeforeStep(source, tokens, i), selCursor);

            var last = i == tokens.Count - 1;
            if (last)
            {
                Assign(selCursor, token, DeepClone(srcCursor), sparseArrays);
            }
            else
            {
                var next = GetOrCreateChild(selCursor, token, srcCursor, sparseArrays);
                selCursor = next;
            }
        }

        return selection;
    }

    private static JsonObject? GetParentObjectBeforeStep(JsonNode source, IReadOnlyList<string> tokens, int index)
    {
        var cursor = source;
        for (var i = 0; i < index; i++)
        {
            cursor = Step(cursor, tokens[i]);
            if (cursor is null)
            {
                return null;
            }
        }

        return cursor as JsonObject;
    }

    private static void CopyTypeMembers(JsonObject? sourceObject, JsonNode selectionCursor)
    {
        if (sourceObject is null || selectionCursor is not JsonObject selObject)
        {
            return;
        }

        // Carry the node's identity (@id / id — including skolem urn:bnid ids) and type
        // members onto every intermediate selection node, so the selection canonicalizes to
        // the same RDF nodes as the corresponding part of the whole document.
        foreach (var key in new[] { "@id", "id", "@type", "type" })
        {
            if (sourceObject.TryGetPropertyValue(key, out var value) && value is not null
                && !selObject.ContainsKey(key))
            {
                selObject[key] = DeepClone(value);
            }
        }
    }

    private static JsonNode? Step(JsonNode? node, string token) => node switch
    {
        JsonObject obj => obj.TryGetPropertyValue(token, out var value) ? value : null,
        JsonArray array when int.TryParse(token, out var index) && index >= 0 && index < array.Count => array[index],
        _ => null,
    };

    private static JsonNode GetOrCreateChild(JsonNode selectionCursor, string token, JsonNode sourceChild,
        Dictionary<JsonArray, HashSet<int>> sparseArrays)
    {
        switch (selectionCursor)
        {
            case JsonObject obj:
                if (obj.TryGetPropertyValue(token, out var existing) && existing is not null)
                {
                    return existing;
                }

                var created = NewContainerLike(sourceChild, sparseArrays);
                obj[token] = created;
                return created;

            case JsonArray array:
                var index = int.Parse(token);
                if (sparseArrays.TryGetValue(array, out var populated)) populated.Add(index);
                while (array.Count <= index)
                {
                    array.Add(null);
                }

                if (array[index] is { } slot)
                {
                    return slot;
                }

                var newChild = NewContainerLike(sourceChild, sparseArrays);
                array[index] = newChild;
                return newChild;

            default:
                throw new InvalidOperationException("Cannot descend into a scalar selection node.");
        }
    }

    private static void Assign(JsonNode selectionCursor, string token, JsonNode? value,
        Dictionary<JsonArray, HashSet<int>> sparseArrays)
    {
        switch (selectionCursor)
        {
            case JsonObject obj:
                obj[token] = value;
                break;
            case JsonArray array:
                var index = int.Parse(token);
                if (sparseArrays.TryGetValue(array, out var populated)) populated.Add(index);
                while (array.Count <= index)
                {
                    array.Add(null);
                }

                array[index] = value;
                break;
            default:
                throw new InvalidOperationException("Cannot assign into a scalar selection node.");
        }
    }

    private static JsonNode NewContainerLike(JsonNode source, Dictionary<JsonArray, HashSet<int>> sparseArrays)
    {
        if (source is not JsonArray) return new JsonObject();
        var array = new JsonArray();
        sparseArrays.Add(array, []);
        return array;
    }

    private static JsonNode? DeepClone(JsonNode? node)
        => node is null ? null : JsonNode.Parse(node.ToJsonString());
}
