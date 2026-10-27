using System.Runtime.InteropServices;
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
/// that a lenient parse left in the element's raw text are skipped, not rejected: they never reach a
/// canonicalizer, and such documents have always verified.
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

    private static readonly JsonReaderOptions ReaderOptions = new()
    {
        MaxDepth = MaxDepth,
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>
    /// Returns why <paramref name="element"/> cannot be processed, as a predicate phrase for a
    /// message ("has a duplicate member name"), or <c>null</c> when it can. The phrase never
    /// quotes the content (FR-23).
    /// </summary>
    /// <param name="element">An element backed by a parsed document (any kind but <see cref="JsonValueKind.Undefined"/>).</param>
    public static string? FindProblem(JsonElement element)
    {
        var utf8 = JsonMarshal.GetRawUtf8Value(element);
        if (!Utf8.IsValid(utf8))
        {
            return "is not valid UTF-8";
        }

        var reader = new Utf8JsonReader(utf8, ReaderOptions);
        var memberNames = new Stack<HashSet<string>>();
        try
        {
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        memberNames.Push(new HashSet<string>(StringComparer.Ordinal));
                        break;
                    case JsonTokenType.EndObject:
                        memberNames.Pop();
                        break;
                    case JsonTokenType.PropertyName:
                        // Compared unescaped, so "a" and its escaped spelling are the same name.
                        if (!memberNames.Peek().Add(reader.GetString()!))
                        {
                            return "has a duplicate member name";
                        }

                        break;
                    case JsonTokenType.String when reader.ValueIsEscaped:
                        _ = reader.GetString();
                        break;
                }
            }
        }
        catch (JsonException)
        {
            // The text came from a successful parse and the reader skips what a lenient parse
            // allows, so only the depth limit can fail here; anything else still fails closed.
            return reader.CurrentDepth >= MaxDepth
                ? $"nests deeper than {MaxDepth} levels"
                : "is not well-formed JSON";
        }
        catch (InvalidOperationException)
        {
            return "contains a JSON escape for an unpaired UTF-16 surrogate";
        }

        return null;
    }

    /// <summary>Throws <see cref="ProofGenerationException"/> when <see cref="FindProblem"/> finds one.</summary>
    /// <param name="element">The JSON to check.</param>
    /// <param name="what">What the JSON is, as a sentence subject ("The document to secure").</param>
    public static void RequireValid(JsonElement element, string what)
    {
        if (FindProblem(element) is { } problem)
        {
            throw new ProofGenerationException($"{what} {problem}.");
        }
    }

    /// <summary>
    /// Checks the caller's raw JSON in <paramref name="proof"/> (<c>@context</c> and extension
    /// members), serializes it, and checks the result.
    /// </summary>
    /// <remarks>
    /// The raw elements are checked as given, because serialization would hide or fail on their
    /// faults: it rewrites invalid UTF-8 as U+FFFD, silently changing what is signed; it throws
    /// <see cref="InvalidOperationException"/> for an element with no value; and it throws
    /// <see cref="JsonException"/> for one it cannot write. The serialized result is checked too:
    /// an extension member whose name repeats a modelled one (<c>proofPurpose</c>) is written twice.
    /// </remarks>
    /// <param name="proof">The proof options or configuration.</param>
    /// <param name="typeInfo">The package's metadata for <see cref="DataIntegrityProof"/>.</param>
    /// <param name="what">What the proof is, as a sentence subject ("The proof configuration").</param>
    /// <returns>The serialized proof, for callers that canonicalize it.</returns>
    /// <exception cref="ProofGenerationException">The proof's JSON fails the check or cannot be serialized.</exception>
    public static JsonElement SerializeChecked(DataIntegrityProof proof, JsonTypeInfo<DataIntegrityProof> typeInfo, string what)
    {
        if (proof.Context is { } context)
        {
            RequireValue(context, what);
        }

        foreach (var value in proof.AdditionalProperties?.Values ?? [])
        {
            RequireValue(value, what);
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

        RequireValid(element, what);
        return element;
    }

    private static void RequireValue(JsonElement element, string what)
    {
        if (element.ValueKind == JsonValueKind.Undefined)
        {
            throw new ProofGenerationException($"{what} has a member with no JSON value.");
        }

        RequireValid(element, what);
    }
}
