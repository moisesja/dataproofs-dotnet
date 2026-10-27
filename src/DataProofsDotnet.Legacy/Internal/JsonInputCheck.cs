using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Text.Unicode;
using DataProofsDotnet.DataIntegrity;

namespace DataProofsDotnet.Legacy.Internal;

/// <summary>
/// Rejects JSON that a Data Integrity entry point cannot process deterministically, before any
/// step reads it: text that is not valid UTF-8, a JSON escape for an unpaired UTF-16 surrogate,
/// a duplicate member name in any object, or nesting deeper than <see cref="MaxDepth"/> levels.
/// </summary>
/// <remarks>
/// <para>
/// A <see cref="JsonElement"/> can carry all four. <see cref="JsonDocument"/> validates structure,
/// not encoding, and transcodes a string only when something reads it; it keeps duplicate members
/// unless the caller asked it not to; and it accepts whatever depth the caller allowed. Each fault
/// then surfaces from a different step as a different exception — <see cref="InvalidOperationException"/>
/// from a member-name comparison (<c>TryGetProperty</c>, <c>JsonObject</c>),
/// <see cref="ArgumentException"/> from a <c>JsonObject</c> materializing a duplicate,
/// <see cref="JsonException"/> from serialization — and which one fires first depends on member
/// order (issue #33).
/// </para>
/// <para>
/// JCS forbids the first three outright: input "MUST be adapted for I-JSON" with no duplicate
/// property names and string data "expressible as Unicode" (RFC 8785 §3.1), and a lone surrogate
/// "MUST cause a compliant JCS implementation to terminate with an appropriate error" (§3.2.2.2).
/// For RDFC they are input whose meaning RFC 8259 leaves "unpredictable" (§4, §8.1, §8.2), which
/// the JSON-LD processor resolves silently — a parser differential between signer and verifier.
/// Depth beyond 64 is what System.Text.Json's serializer, and so every transformation step here,
/// already refuses.
/// </para>
/// <para>
/// One pass over the element's UTF-8 bytes closes all four, so after this check every member name
/// and string reads back through any API, and every later step sees the same document. Unescaped
/// tokens need no transcode: validated UTF-8 cannot encode a surrogate. Comments and trailing commas
/// that a lenient parse left in the element's raw text are not faults, but some later steps re-parse
/// raw text strictly (proof embedding, bbs-2023 skolemization). So <see cref="TryAccept"/> and
/// <see cref="RequireValid"/> hand back a strict copy of such an element, and every entry point
/// carries on with that copy (PR #35 review).
/// </para>
/// <para>
/// Vendored verbatim from <c>DataProofsDotnet.Core/Internal/JsonInputCheck.cs</c> (the
/// <c>EcdsaSignatureEncoding</c> precedent), so this assembly stays self-contained and does not
/// widen Core's <c>InternalsVisibleTo</c>. Keep the copies identical.
/// </para>
/// </remarks>
internal static class JsonInputCheck
{
    /// <summary>The deepest nesting accepted: System.Text.Json's default, which its serializer enforces.</summary>
    public const int MaxDepth = 64;

    // A member-name set is reused by the next object at the same depth unless the last object
    // there was wide: Clear() costs the set's capacity, so reusing a set that once held thousands
    // of names for every following sibling would be quadratic.
    private const int ReusableSetSize = 16;

    private static readonly JavaScriptEncoder Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping;

    /// <summary>
    /// Returns why <paramref name="element"/> cannot be processed, as a predicate phrase for a
    /// message ("has a duplicate member name"), or <c>null</c> when it can. The phrase never
    /// quotes the content (FR-23).
    /// </summary>
    /// <param name="element">An element backed by a parsed document (any kind but <see cref="JsonValueKind.Undefined"/>).</param>
    /// <param name="maxDepth">The deepest nesting accepted, lower than <see cref="MaxDepth"/> for JSON that will sit inside another document.</param>
    public static string? FindProblem(JsonElement element, int maxDepth = MaxDepth)
        => FindProblem(element, maxDepth, out _);

    /// <summary>
    /// Checks <paramref name="element"/>; on success, <paramref name="accepted"/> is the element
    /// itself, or a strict copy when its raw text holds comments or trailing commas.
    /// </summary>
    public static bool TryAccept(JsonElement element, out JsonElement accepted, [NotNullWhen(false)] out string? problem)
    {
        problem = FindProblem(element, MaxDepth, out var lenient);
        accepted = problem is null && lenient ? StrictCopy(element) : element;
        return problem is null;
    }

    /// <summary>Like <see cref="TryAccept"/>, but throws <see cref="ProofGenerationException"/> on a problem.</summary>
    /// <param name="element">The JSON to check.</param>
    /// <param name="what">What the JSON is, as a sentence subject ("The document to secure").</param>
    /// <param name="maxDepth">The deepest nesting accepted.</param>
    /// <returns>The element to carry on with: itself, or its strict copy.</returns>
    public static JsonElement RequireValid(JsonElement element, string what, int maxDepth = MaxDepth)
    {
        if (FindProblem(element, maxDepth, out var lenient) is { } problem)
        {
            throw new ProofGenerationException($"{what} {problem}.");
        }

        return lenient ? StrictCopy(element) : element;
    }

    /// <summary>
    /// Checks the caller's raw JSON in <paramref name="proof"/> (<c>@context</c> and extension
    /// members), serializes it, and checks the result.
    /// </summary>
    /// <remarks>
    /// The raw elements are checked as given, because serialization would hide or fail on their
    /// faults: it rewrites invalid UTF-8 as U+FFFD, silently changing what is signed; it throws
    /// <see cref="InvalidOperationException"/> for an element with no value; and it throws
    /// <see cref="JsonException"/> for one it cannot write. Extension names must not match any
    /// modelled JSON member, even one currently omitted: creation populates <c>proofValue</c>
    /// later, and an extension with that name would then be written twice. The names come from
    /// source-generated metadata, without reflection. The serialized result is checked too, against
    /// <paramref name="maxDepth"/>: a proof is embedded in the secured document, so its own depth
    /// budget is smaller than the document's.
    /// </remarks>
    /// <param name="proof">The proof options or configuration.</param>
    /// <param name="typeInfo">The package's metadata for <see cref="DataIntegrityProof"/>.</param>
    /// <param name="what">What the proof is, as a sentence subject ("The proof configuration").</param>
    /// <param name="maxDepth">The deepest nesting the serialized proof may have.</param>
    /// <returns>The serialized proof, for callers that canonicalize it.</returns>
    /// <exception cref="ProofGenerationException">The proof's JSON fails the check or cannot be serialized.</exception>
    public static JsonElement SerializeChecked(
        DataIntegrityProof proof, JsonTypeInfo<DataIntegrityProof> typeInfo, string what, int maxDepth = MaxDepth)
    {
        if (proof.Context is { } context)
        {
            RequireValue(context, what);
        }

        foreach (var member in proof.AdditionalProperties?.AsEnumerable() ?? [])
        {
            if (typeInfo.Properties.Any(property => !property.IsExtensionData
                && string.Equals(property.Name, member.Key, StringComparison.Ordinal)))
            {
                throw new ProofGenerationException($"{what} has an extension member with a reserved proof name.");
            }

            RequireValue(member.Value, what);
        }

        JsonElement element;
        try
        {
            element = JsonSerializer.SerializeToElement(proof, typeInfo);
        }
        catch (JsonException ex)
        {
            throw new ProofGenerationException($"{what} could not be serialized as JSON.", ex);
        }

        // Serialized output is strict JSON, so this never needs the copy.
        return RequireValid(element, what, maxDepth);
    }

    private static string? FindProblem(JsonElement element, int maxDepth, out bool lenient)
    {
        lenient = false;
        var utf8 = JsonMarshal.GetRawUtf8Value(element);
        if (!Utf8.IsValid(utf8))
        {
            return "is not valid UTF-8";
        }

        // Comments are read as tokens rather than skipped, so the pass can tell a lenient text
        // from a strict one; trailing commas are accepted and detected from the raw bytes.
        var reader = new Utf8JsonReader(utf8, new JsonReaderOptions
        {
            MaxDepth = maxDepth,
            CommentHandling = JsonCommentHandling.Allow,
            AllowTrailingCommas = true,
        });

        // One name set per depth, indexed by the depth of the members it holds (an object's
        // members are one level below its start token).
        var memberNames = new HashSet<string>?[maxDepth + 1];
        try
        {
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        ref var names = ref memberNames[reader.CurrentDepth + 1];
                        if (names is null || names.Count > ReusableSetSize)
                        {
                            names = new HashSet<string>(StringComparer.Ordinal);
                        }
                        else
                        {
                            names.Clear();
                        }

                        break;
                    case JsonTokenType.PropertyName:
                        // Compared unescaped, so "a" and its escaped spelling are the same name.
                        if (!memberNames[reader.CurrentDepth]!.Add(reader.GetString()!))
                        {
                            return "has a duplicate member name";
                        }

                        break;
                    case JsonTokenType.String when reader.ValueIsEscaped:
                        _ = reader.GetString();
                        break;
                    case JsonTokenType.Comment:
                        lenient = true;
                        break;
                    case JsonTokenType.EndObject or JsonTokenType.EndArray when !lenient:
                        lenient = FollowsComma(utf8, (int)reader.TokenStartIndex);
                        break;
                }
            }
        }
        catch (JsonException)
        {
            // The text came from a successful parse and the reader accepts what a lenient parse
            // allows, so only the depth limit can fail here; anything else still fails closed.
            // The reader stops on its last good token: a member name inside the deepest object
            // (depth maxDepth) or, in nested arrays, the deepest start token (maxDepth - 1).
            return reader.CurrentDepth >= maxDepth - 1
                ? $"nests deeper than {maxDepth} levels"
                : "is not well-formed JSON";
        }
        catch (InvalidOperationException)
        {
            return "contains a JSON escape for an unpaired UTF-16 surrogate";
        }

        return null;
    }

    // Whether the closing bracket at `end` is preceded, past whitespace, by a comma: a trailing
    // comma. A comment in between is already reported as its own token.
    private static bool FollowsComma(ReadOnlySpan<byte> utf8, int end)
    {
        var index = utf8[..end].TrimEnd(" \t\r\n"u8).Length - 1;
        return index >= 0 && utf8[index] == (byte)',';
    }

    // The same JSON without comments or trailing commas: the element model holds neither, so
    // writing it out drops both. Only called after the check passed, so the write cannot fail
    // and the parse accepts the depth.
    private static JsonElement StrictCopy(JsonElement element)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Encoder = Encoder }))
        {
            element.WriteTo(writer);
        }

        using var document = JsonDocument.Parse(buffer.WrittenMemory);
        return document.RootElement.Clone();
    }

    private static void RequireValue(JsonElement element, string what)
    {
        if (element.ValueKind == JsonValueKind.Undefined)
        {
            throw new ProofGenerationException($"{what} has a member with no JSON value.");
        }

        _ = RequireValid(element, what);
    }
}
