using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using VDS.RDF.JsonLd;
using VDS.RDF.Parsing;

namespace DataProofsDotnet.Rdfc.Internal;

/// <summary>
/// Finds the JSON-LD input that dotNetRDF's deserialization to RDF would drop, so the
/// canonicalizer can fail closed instead of signing less than the document says (issue #36).
/// </summary>
/// <remarks>
/// <para>
/// dotNetRDF loses data in two phases. Expansion drops terms the <c>@context</c> does not define
/// and malformed language tags, and reports them only as <see cref="JsonLdProcessorOptions.SafeMode"/>
/// warnings. Deserialization of the expanded form skips every IRI that is not a well-formed
/// absolute IRI (subjects, types, properties, objects, named-graph names, list members), skips
/// blank-node properties, and ignores <c>@direction</c> and <c>@index</c>. It reports only some of
/// those skips, even in safe mode: a named graph, a property or a list member disappears without
/// a warning.
/// </para>
/// <para>
/// So <see cref="FindLoss(string, JsonLdProcessorOptions)"/> expands the input exactly as
/// <c>JsonLdParser.Load</c> does, fails on any expansion warning, and then applies dotNetRDF's own
/// IRI test to every position of the expanded form. IRIs that survive but would be respelled in
/// the canonical N-Quads are caught where they are emitted, by <see cref="ExactIriStoreHandler"/>.
/// Each result is a predicate phrase for a message ("uses a term that…") and never quotes the
/// input (FR-23).
/// </para>
/// </remarks>
internal static class JsonLdLossAudit
{
    public const string UndefinedTerm = "uses a term that its @context does not define";
    public const string MalformedIri = "has an IRI that is not a well-formed absolute IRI";
    public const string MalformedLanguageTag = "has a language tag that is not well-formed";
    public const string BlankNodeProperty = "uses a blank node as a property, which RDF cannot carry";
    public const string Direction = "uses @direction, which the canonical form does not carry";
    public const string Index = "uses @index, which the canonical form does not carry";
    public const string RespelledIri = "has an IRI that the canonical form would spell differently";
    public const string IgnoredContent = "has content that JSON-LD processing ignores";

    /// <summary>
    /// Expands <paramref name="json"/> as <c>JsonLdParser.Load</c> does and returns why its RDF
    /// form would lose part of it, or <see langword="null"/> when nothing would be dropped.
    /// </summary>
    /// <remarks>Processing faults (invalid JSON-LD, a context the loader refuses) propagate.</remarks>
    public static string? FindLoss(string json, JsonLdProcessorOptions options)
    {
        JToken input;
        using (var reader = new JsonTextReader(new StringReader(json)) { DateParseHandling = DateParseHandling.None })
        {
            input = JToken.ReadFrom(reader);
        }

        var warnings = new List<JsonLdProcessorWarning>();
        var expanded = JsonLdProcessor.Expand(input, options, warnings);
        if (warnings.Count > 0)
        {
            return warnings[0].ErrorCode switch
            {
                JsonLdErrorCode.InvalidIriMapping => UndefinedTerm,
                JsonLdErrorCode.MalformedLanguageTag => MalformedLanguageTag,
                _ => IgnoredContent,
            };
        }

        foreach (var item in expanded)
        {
            if (FindInNode(item) is { } loss)
            {
                return loss;
            }
        }

        return null;
    }

    // A node object of the expanded form (graph objects and node references included).
    private static string? FindInNode(JToken token)
    {
        if (token is not JObject node)
        {
            return IgnoredContent;
        }

        foreach (var member in node.Properties())
        {
            var loss = member.Name switch
            {
                "@id" => FindInIri(member.Value, allowBlankNode: true),
                "@type" => FindInEach(member.Value, t => FindInIri(t, allowBlankNode: true)),
                "@graph" or "@included" => FindInEach(member.Value, FindInNode),
                "@reverse" => FindInReverse(member.Value),
                "@index" => Index,
                _ when member.Name.StartsWith('@') => IgnoredContent,
                _ => FindInIri(member.Name, allowBlankNode: false) ?? FindInEach(member.Value, FindInValue),
            };

            if (loss is not null)
            {
                return loss;
            }
        }

        return null;
    }

    // One entry of a property's value array: a value object, a list object or a node object.
    private static string? FindInValue(JToken token)
    {
        if (token is not JObject obj)
        {
            return IgnoredContent;
        }

        if (obj.ContainsKey("@value"))
        {
            return FindInValueObject(obj);
        }

        if (obj.ContainsKey("@list"))
        {
            return obj.ContainsKey("@index") ? Index : FindInEach(obj["@list"], FindInValue);
        }

        return FindInNode(obj);
    }

    private static string? FindInValueObject(JObject value)
    {
        if (value.ContainsKey("@direction"))
        {
            return Direction;
        }

        if (value.ContainsKey("@index"))
        {
            return Index;
        }

        if (value.TryGetValue("@language", out var language)
            && (language.Type != JTokenType.String || !LanguageTag.IsWellFormed((string)language!)))
        {
            return MalformedLanguageTag;
        }

        if (value.TryGetValue("@type", out var datatype) && !IsJsonLiteral(datatype))
        {
            return FindInIri(datatype, allowBlankNode: false);
        }

        return null;
    }

    private static string? FindInReverse(JToken token)
    {
        if (token is not JObject reverse)
        {
            return IgnoredContent;
        }

        foreach (var member in reverse.Properties())
        {
            if ((FindInIri(member.Name, allowBlankNode: false) ?? FindInEach(member.Value, FindInNode)) is { } loss)
            {
                return loss;
            }
        }

        return null;
    }

    private static string? FindInEach(JToken? token, Func<JToken, string?> find)
    {
        if (token is not JArray array)
        {
            return IgnoredContent;
        }

        foreach (var item in array)
        {
            if (find(item) is { } loss)
            {
                return loss;
            }
        }

        return null;
    }

    private static string? FindInIri(JToken token, bool allowBlankNode)
        => token.Type == JTokenType.String ? FindInIri((string)token!, allowBlankNode) : IgnoredContent;

    // dotNetRDF's own test for every IRI it emits: an absolute URI whose original string is well
    // formed. A blank node identifier is kept where RDF allows one (not as a property or datatype).
    private static string? FindInIri(string iri, bool allowBlankNode)
    {
        if (iri.StartsWith("_:", StringComparison.Ordinal))
        {
            return allowBlankNode ? null : BlankNodeProperty;
        }

        return Uri.TryCreate(iri, UriKind.Absolute, out var uri) && uri.IsWellFormedOriginalString()
            ? null
            : MalformedIri;
    }

    private static bool IsJsonLiteral(JToken datatype)
        => datatype.Type == JTokenType.String && (string)datatype! == "@json";
}
