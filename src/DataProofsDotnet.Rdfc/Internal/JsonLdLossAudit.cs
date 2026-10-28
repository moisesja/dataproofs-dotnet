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
/// So <see cref="FindLoss(string, JsonLdContextCache)"/> expands the input exactly as
/// <c>JsonLdParser.Load</c> does, fails on any expansion warning, and then applies dotNetRDF's own
/// IRI test to every position of the expanded form. IRIs that survive but would be respelled in
/// the canonical N-Quads are caught where they are emitted, by <see cref="ExactIriStoreHandler"/>.
/// One respelling happens earlier, where that check cannot see it: dotNetRDF resolves a relative
/// IRI against <c>@base</c> with <see cref="Uri"/>, which also decodes percent-escapes and normalizes
/// case and port, so the expanded string is already respelled. So when the input or a context it
/// loads holds a <c>@base</c> member, the input is expanded again with every <c>@base</c> removed
/// from both, and any difference outside JSON literal payloads means a relative IRI was resolved:
/// refused. A <c>@base</c> that resolves nothing, or a <c>"@base"</c> key that is only data inside a
/// JSON literal, passes (PR #37 review). Loaded contexts count because dotNetRDF honors a
/// <c>@base</c> in a scoped context that a remote context defines, though it ignores the remote
/// context's own (JSON-LD 1.1 §4.1.2; adversarial review, F1). dotNetRDF fails on <c>@import</c>
/// while the base is null.
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
    public const string MergedTerms = "has distinct terms that the canonical form would merge into one";
    public const string IgnoredContent = "has content that JSON-LD processing ignores";
    public const string Base = "resolves a relative IRI against @base, which the canonical form would respell";
    public const string UnpairedSurrogate = "has an unpaired UTF-16 surrogate, which UTF-8 cannot carry";
    public const string NonFiniteNumber = "has a number too large for a double, which the canonical form cannot carry";

    /// <summary>
    /// Expands <paramref name="json"/> as <c>JsonLdParser.Load</c> does and returns why its RDF
    /// form would lose part of it, or <see langword="null"/> when nothing would be dropped.
    /// </summary>
    /// <remarks>Processing faults (invalid JSON-LD, a context the loader refuses) propagate.</remarks>
    public static string? FindLoss(string json, JsonLdContextCache contexts)
    {
        var input = ReadJson(json);

        // Newtonsoft reads a number beyond the double range as an infinity, so 1e400 and 2e400 would
        // sign as one "Infinity", inside @json literals too (adversarial review, F5).
        if (HasNonFiniteNumber(input))
        {
            return NonFiniteNumber;
        }

        var inputSetsBase = HasBase(input);

        var warnings = new List<JsonLdProcessorWarning>();
        var expanded = JsonLdProcessor.Expand(input, contexts.Options(withoutBase: false), warnings);
        if (warnings.Count > 0)
        {
            return warnings[0].ErrorCode switch
            {
                JsonLdErrorCode.InvalidIriMapping => UndefinedTerm,
                JsonLdErrorCode.MalformedLanguageTag => MalformedLanguageTag,
                _ => IgnoredContent,
            };
        }

        if ((inputSetsBase || contexts.AnySetsBase) && ResolvesAgainstBase(expanded, json, contexts))
        {
            return Base;
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
            && (language.Type != JTokenType.String || !IsWellFormedLanguageTag((string)language!)))
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

    private static JToken ReadJson(string json)
    {
        using var reader = new JsonTextReader(new StringReader(json)) { DateParseHandling = DateParseHandling.None };
        return JToken.ReadFrom(reader);
    }

    // dotNetRDF's pattern ends in $, which also matches before a final newline, so "en\n" passed and
    // put a raw line break into the quad (adversarial review, F3). BCP 47 tags are ASCII
    // letters, digits and hyphens.
    private static bool IsWellFormedLanguageTag(string tag)
        => tag.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') && LanguageTag.IsWellFormed(tag);

    private static bool HasNonFiniteNumber(JToken token) => token switch
    {
        JValue { Type: JTokenType.Float, Value: double number } => !double.IsFinite(number),
        JContainer container => container.Children().Any(HasNonFiniteNumber),
        _ => false,
    };

    // Whether a JSON-LD document or context holds a non-null @base member at any depth: a cheap
    // trigger for the check below, which tells a context's @base from a "@base" key that is only data.
    public static bool HasBase(JToken token) => token switch
    {
        JObject obj => obj.Properties().Any(p => (p.Name == "@base" && p.Value.Type != JTokenType.Null) || HasBase(p.Value)),
        JArray array => array.Any(HasBase),
        _ => false,
    };

    public static JToken WithoutBase(JToken input)
    {
        // HasBase found a member, so the input is an object or array.
        var copy = (JContainer)input.DeepClone();
        foreach (var member in copy.Descendants().OfType<JProperty>().Where(p => p.Name == "@base").ToList())
        {
            member.Remove();
        }

        return copy;
    }

    // Whether a @base changed the expansion. Expanding without it (in the input and in every loaded
    // context) fails when something needed it, such as a relative context URL; otherwise the two
    // expansions match unless an IRI was resolved.
    private static bool ResolvesAgainstBase(JArray expanded, string json, JsonLdContextCache contexts)
    {
        var input = ReadJson(json);
        if (HasBase(input))
        {
            input = WithoutBase(input);
        }

        JArray unresolved;
        try
        {
            unresolved = JsonLdProcessor.Expand(input, contexts.Options(withoutBase: true), new List<JsonLdProcessorWarning>());
        }
        catch (Exception)
        {
            return true;
        }

        return !SameOutsideJsonLiterals(expanded, unresolved);
    }

    // Deep equality that does not look inside JSON literal payloads, which are opaque data: removing
    // a "@base" key from one changes the payload but resolves nothing.
    private static bool SameOutsideJsonLiterals(JToken a, JToken b)
    {
        switch (a, b)
        {
            case (JObject x, JObject y):
                if (IsJsonLiteralValue(x) && IsJsonLiteralValue(y))
                {
                    return true;
                }

                return x.Count == y.Count
                    && x.Properties().All(p => y.TryGetValue(p.Name, out var other) && SameOutsideJsonLiterals(p.Value, other));
            case (JArray x, JArray y):
                return x.Count == y.Count && x.Zip(y).All(pair => SameOutsideJsonLiterals(pair.First, pair.Second));
            default:
                return JToken.DeepEquals(a, b);
        }
    }

    private static bool IsJsonLiteralValue(JObject value)
        => value.ContainsKey("@value") && value.TryGetValue("@type", out var datatype) && IsJsonLiteral(datatype);

    private static bool IsJsonLiteral(JToken datatype)
        => datatype.Type == JTokenType.String && (string)datatype! == "@json";
}
