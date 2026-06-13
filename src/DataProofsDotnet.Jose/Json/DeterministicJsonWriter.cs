using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.Json;

/// <summary>
/// Writes a <see cref="JsonNode"/> to a UTF-8 byte sequence in a reproducible canonical form:
/// no whitespace, object members sorted ASCII-lexicographically by key at every nesting level.
/// </summary>
/// <remarks>
/// <para>
/// NFR-5 mandates that the bytes fed into a JWS signing input or a JWE AAD are reproducible
/// given the same logical content, regardless of original key order or incidental whitespace.
/// <see cref="System.Text.Json"/> preserves insertion order, so we walk the tree and emit a
/// sorted copy here. Ported from didcomm-dotnet <c>DidComm.Json.DeterministicJsonWriter</c>.
/// </para>
/// <para>
/// This is JCS-flavored but deliberately not full RFC 8785: number canonicalization is not
/// done (JOSE headers that take numbers are always JSON integers, so no float normalization is
/// needed). If a future header forces fractional numbers, swap to NetCid's
/// <c>JcsCanonicalizer</c> at that point.
/// </para>
/// </remarks>
internal static class DeterministicJsonWriter
{
    /// <summary>Serialize <paramref name="node"/> into a canonical UTF-8 byte sequence.</summary>
    public static byte[] WriteUtf8(JsonNode? node)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Indented = false,
            SkipValidation = false,
            // Match JoseJson.Default so the canonical bytes do not double-escape characters
            // like '+' that the JOSE spec vectors carry literally.
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        }))
        {
            WriteNode(writer, node);
        }
        return stream.ToArray();
    }

    /// <summary>Serialize <paramref name="node"/> into a canonical UTF-8 string.</summary>
    public static string WriteString(JsonNode? node)
        => Encoding.UTF8.GetString(WriteUtf8(node));

    private static void WriteNode(Utf8JsonWriter writer, JsonNode? node)
    {
        switch (node)
        {
            case null:
                writer.WriteNullValue();
                return;
            case JsonObject obj:
                writer.WriteStartObject();
                foreach (var kvp in obj.OrderBy(p => p.Key, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(kvp.Key);
                    WriteNode(writer, kvp.Value);
                }
                writer.WriteEndObject();
                return;
            case JsonArray arr:
                writer.WriteStartArray();
                foreach (var item in arr)
                    WriteNode(writer, item);
                writer.WriteEndArray();
                return;
            case JsonValue val:
                val.WriteTo(writer);
                return;
            default:
                throw new InvalidOperationException($"Unsupported JsonNode kind: {node.GetType().Name}");
        }
    }
}
