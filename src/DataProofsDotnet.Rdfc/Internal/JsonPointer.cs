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

        foreach (var pointer in pointers)
        {
            var tokens = Parse(pointer);
            selection = SelectPath(source, tokens, selection);
        }

        if (selection is JsonObject selectionObject)
        {
            // Carry @context verbatim so the selection re-expands under the same vocabulary.
            if (document.TryGetProperty("@context", out var context))
            {
                selectionObject["@context"] = JsonNode.Parse(context.GetRawText());
            }
        }

        // The index-preserving build leaves null gaps where array elements were not selected;
        // remove them so the selection is dense JSON-LD. Blank-node subjects keep HMAC-stable
        // labels regardless of array position, so the n-quads still match the full document's.
        CompactArrays(selection);
        return selection;
    }

    private static void CompactArrays(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var property in obj.ToArray())
                {
                    CompactArrays(property.Value);
                }

                break;

            case JsonArray array:
                var kept = new List<JsonNode?>(array.Count);
                foreach (var element in array.ToArray())
                {
                    if (element is not null)
                    {
                        kept.Add(element);
                    }
                }

                array.Clear();
                foreach (var element in kept)
                {
                    CompactArrays(element);
                    array.Add(element);
                }

                break;
        }
    }

    // Walks one pointer path against the source, materializing the addressed value into the
    // accumulating selection (creating intermediate containers and copying type members).
    private static JsonNode? SelectPath(JsonNode source, IReadOnlyList<string> tokens, JsonNode? selection)
    {
        var sourceCursor = source;

        // The path's value must exist in the source; a pointer addressing nothing is skipped.
        foreach (var token in tokens)
        {
            sourceCursor = Step(sourceCursor, token);
            if (sourceCursor is null)
            {
                return selection;
            }
        }

        // Re-walk, mirroring the structure into the selection and copying type members.
        selection ??= NewContainerLike(source);
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
                Assign(selCursor, token, DeepClone(srcCursor));
            }
            else
            {
                var next = GetOrCreateChild(selCursor, token, srcCursor);
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

    private static JsonNode GetOrCreateChild(JsonNode selectionCursor, string token, JsonNode sourceChild)
    {
        switch (selectionCursor)
        {
            case JsonObject obj:
                if (obj.TryGetPropertyValue(token, out var existing) && existing is not null)
                {
                    return existing;
                }

                var created = NewContainerLike(sourceChild);
                obj[token] = created;
                return created;

            case JsonArray array:
                var index = int.Parse(token);
                while (array.Count <= index)
                {
                    array.Add(null);
                }

                if (array[index] is { } slot)
                {
                    return slot;
                }

                var newChild = NewContainerLike(sourceChild);
                array[index] = newChild;
                return newChild;

            default:
                throw new InvalidOperationException("Cannot descend into a scalar selection node.");
        }
    }

    private static void Assign(JsonNode selectionCursor, string token, JsonNode? value)
    {
        switch (selectionCursor)
        {
            case JsonObject obj:
                obj[token] = value;
                break;
            case JsonArray array:
                var index = int.Parse(token);
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

    private static JsonNode NewContainerLike(JsonNode source)
        => source is JsonArray ? new JsonArray() : new JsonObject();

    private static JsonNode? DeepClone(JsonNode? node)
        => node is null ? null : JsonNode.Parse(node.ToJsonString());
}
