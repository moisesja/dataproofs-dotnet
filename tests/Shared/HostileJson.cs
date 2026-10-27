using System.Text;
using System.Text.Json;

namespace DataProofsDotnet.Tests.Shared;

/// <summary>
/// Builders for the issue #33 regression suites, linked into Core.Tests, Rdfc.Tests and
/// Legacy.Tests. Every escape is built at run time from its code unit, so the source holds
/// nothing an editor or tool can decode into the literal character (issue #30 lesson), and
/// every splice fails loudly if it did not change the text, so no case can test the original
/// document by accident.
/// </summary>
internal static class HostileJson
{
    public const string Context = "https://www.w3.org/ns/credentials/v2";

    // The check's message phrases (JsonInputCheck.FindProblem), asserted exactly so that every
    // negative case fails against the pre-fix code whichever way that code mishandled the input.
    public const string Surrogate = "contains a JSON escape for an unpaired UTF-16 surrogate";
    public const string Duplicate = "has a duplicate member name";
    public const string ReservedName = "has an extension member with a reserved proof name";

    public static readonly string[] ReservedProofNames =
    [
        "id", "type", "cryptosuite", "created", "expires", "verificationMethod", "proofPurpose",
        "challenge", "domain", "nonce", "previousProof", "@context", "proofValue",
    ];

    public const string TooDeep = "nests deeper than 64 levels";
    public const string NotUtf8 = "is not valid UTF-8";

    /// <summary>The four unpaired-surrogate escapes of the issue #30 suite, by name.</summary>
    public static readonly string[] LoneEscapeNames = ["D800", "DC00", "D800A", "D800D800"];

    /// <summary>The six-character JSON escape for one UTF-16 code unit.</summary>
    public static string Esc(int codeUnit) => @"\u" + codeUnit.ToString("X4");

    public static string LoneEscape(string name) => name switch
    {
        "D800" => Esc(0xD800),
        "DC00" => Esc(0xDC00),
        "D800A" => Esc(0xD800) + "A",
        "D800D800" => Esc(0xD800) + Esc(0xD800),
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, null),
    };

    /// <summary>A minimal JSON-LD document over the VCDM 2.0 context.</summary>
    public static string BaseDocument => "{\"@context\":[\"" + Context + "\"],\"a\":1}";

    /// <summary>
    /// Parses as a caller might: depth up to 256 and duplicates kept, so the hostile content
    /// reaches the code under test instead of failing in this helper.
    /// </summary>
    public static JsonElement Parse(string json) => Parse(Encoding.UTF8.GetBytes(json));

    public static JsonElement Parse(byte[] utf8)
    {
        using var document = JsonDocument.Parse(utf8, new JsonDocumentOptions { MaxDepth = 256, AllowDuplicateProperties = true });
        return document.RootElement.Clone();
    }

    /// <summary>Parses allowing comments and trailing commas, which stay in the element's raw text.</summary>
    public static JsonElement ParseLenient(string json)
    {
        using var document = JsonDocument.Parse(
            json, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
        return document.RootElement.Clone();
    }

    /// <summary><paramref name="levels"/> nested objects, <c>{"a":{"a":…1…}}</c>.</summary>
    public static string Nest(int levels)
        => string.Concat(Enumerable.Repeat("{\"a\":", levels)) + "1" + new string('}', levels);

    public static string FirstMember(string objectJson, string member)
    {
        Require(objectJson.StartsWith('{'), "an object");
        return "{" + member + "," + objectJson[1..];
    }

    public static string LastMember(string objectJson, string member)
    {
        Require(objectJson.EndsWith('}'), "an object");
        return objectJson[..^1] + "," + member + "}";
    }

    /// <summary>Adds <paramref name="member"/> to every proof, just before its <c>proofValue</c>.</summary>
    public static string InProof(string securedJson, string member) => Splice(securedJson, "\"proofValue\"", member + ",\"proofValue\"");

    public static string Splice(string json, string oldValue, string newValue)
    {
        var result = json.Replace(oldValue, newValue, StringComparison.Ordinal);
        Require(!ReferenceEquals(result, json) && result != json, $"'{oldValue}' in the document");
        return result;
    }

    /// <summary>The UTF-8 of <paramref name="json"/> with the ASCII <paramref name="marker"/> overwritten by <paramref name="bytes"/>.</summary>
    public static byte[] WithBytes(string json, string marker, params byte[] bytes)
    {
        Require(marker.Length == bytes.Length, "a marker as long as the bytes");
        var utf8 = Encoding.UTF8.GetBytes(json);
        var index = utf8.AsSpan().IndexOf(Encoding.ASCII.GetBytes(marker));
        Require(index >= 0, $"'{marker}' in the document");
        bytes.CopyTo(utf8, index);
        return utf8;
    }

    /// <summary>Re-spells every non-ASCII UTF-16 code unit as a JSON escape (valid: they occur only in strings).</summary>
    public static string EscapeNonAscii(string json)
    {
        var builder = new StringBuilder(json.Length);
        foreach (var c in json)
        {
            builder.Append(c < 0x80 ? c.ToString() : Esc(c));
        }

        return builder.ToString();
    }

    private static void Require(bool condition, string what)
    {
        if (!condition)
        {
            throw new InvalidOperationException($"Test fixture construction expected {what}.");
        }
    }
}
