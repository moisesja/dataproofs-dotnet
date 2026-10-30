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
/// blank-node properties, and ignores <c>@index</c>. It reports only some of those skips, even in
/// safe mode: a named graph, a property or a list member disappears without a warning. A string's
/// <c>@direction</c> is carried, because <see cref="JsonLdContextCache.Options"/> sets
/// <c>rdfDirection: i18n-datatype</c> (issue #40); a boolean's or a number's is still dropped, since
/// those become XSD literals first (JSON-LD 1.1 API §8.6), so it is refused.
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
/// </para>
/// <para>
/// Expansion also drops some <c>@index</c> entries without a warning: a set object's
/// (<c>{"@set": [...], "@index": "x"}</c>) and a null value's, so the walk never sees them. Which keys
/// expand to <c>@index</c> is for the processor to decide: aliases chain through other terms and
/// hold only in their scope (PR #37 reviews). So when the input or a context it loads names
/// <c>@index</c>, the input is expanded once more with every <c>"@index"</c> key outside contexts,
/// and every term a context defines as <c>@index</c>, naming a fresh unpredictable IRI instead
/// (<see cref="WithIndexAs"/>). The processor then resolves every alias to that IRI in its own active
/// context, and a term in a scope it never activates changes nothing. The probe differs from the
/// input only at keys that expand to <c>@index</c>, and the walk refused every <c>@index</c> that
/// survived. So if the probe fails (a set or value object takes no property), warns, or expands to
/// anything else outside JSON literal payloads, which expansion does not read, an <c>@index</c> was
/// dropped: refused.
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
    public const string Direction = "uses @direction on a value that is not a string, which the canonical form does not carry";
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
        var inputNamesIndex = NamesIndex(input);

        var warnings = new List<JsonLdProcessorWarning>();
        var expanded = JsonLdProcessor.Expand(input, contexts.Options(), warnings);
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

        if ((inputNamesIndex || contexts.AnyNamesIndex) && DropsAnIndex(expanded, json, contexts))
        {
            return Index;
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
        // A string's direction goes into its i18n datatype (JsonLdContextCache.Options). A boolean or
        // a number becomes an XSD literal before that step (JSON-LD 1.1 API §8.6), and its direction
        // is dropped without a warning (issue #40). A @type beside @direction fails expansion earlier.
        if (value.ContainsKey("@direction") && value["@value"]?.Type != JTokenType.String)
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
        var copy = input.DeepClone();
        foreach (var member in (copy as JContainer)?.Descendants().OfType<JProperty>().Where(p => p.Name == "@base").ToList() ?? [])
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
        JArray unresolved;
        try
        {
            unresolved = JsonLdProcessor.Expand(WithoutBase(ReadJson(json)), contexts.Options(WithoutBase), new List<JsonLdProcessorWarning>());
        }
        catch (Exception)
        {
            return true;
        }

        return !SameOutsideJsonLiterals(expanded, unresolved);
    }

    // Whether a JSON-LD document or context document names @index: a cheap trigger for the check below.
    public static bool NamesIndex(JToken token) => IndexMembers(token).Count > 0;

    /// <summary>
    /// A copy of a JSON-LD document or context document in which nothing expands to <c>@index</c>:
    /// each member <see cref="IndexMembers"/> finds names <paramref name="probe"/> instead. Every
    /// alias defined through one of those terms follows it, in whatever scope the processor finds it.
    /// </summary>
    public static JToken WithIndexAs(JToken input, string probe)
    {
        var copy = input.DeepClone();

        // Innermost first: renaming a key replaces its member, and with it the members inside.
        foreach (var member in Enumerable.Reverse(IndexMembers(copy)))
        {
            if (member.Name == "@index")
            {
                member.Replace(new JProperty(probe, member.Value));
            }
            else
            {
                member.Value = probe;
            }
        }

        return copy;
    }

    // Whether expansion dropped an @index the walk could not see (see the remarks). The probe differs
    // from the input only at keys that expand to @index, so wherever it fails, warns or expands to
    // something else outside JSON literal payloads, expansion processed one of them.
    private static bool DropsAnIndex(JArray expanded, string json, JsonLdContextCache contexts)
    {
        // Unpredictable, so no input or context can define it as a term.
        var probe = "urn:uuid:" + Guid.NewGuid().ToString("D");
        var warnings = new List<JsonLdProcessorWarning>();
        JArray probed;
        try
        {
            probed = JsonLdProcessor.Expand(WithIndexAs(ReadJson(json), probe), contexts.Options(c => WithIndexAs(c, probe)), warnings);
        }
        catch (JsonLdProcessorException)
        {
            // A set or value object, which takes no property, now holds one.
            return true;
        }

        return warnings.Count > 0 || !SameOutsideJsonLiterals(expanded, probed);
    }

    // The members of a JSON-LD document or context document that can expand to @index, outer ones
    // first: each "@index" key outside contexts, and, in contexts (scoped ones included), each term
    // defined as @index or the @id that defines it. Any other alias reaches @index through one of them.
    private static List<JProperty> IndexMembers(JToken token)
    {
        var found = new List<JProperty>();
        CollectIndexKeys(token, found);
        return found;
    }

    private static void CollectIndexKeys(JToken token, List<JProperty> found)
    {
        switch (token)
        {
            case JArray array:
                foreach (var item in array)
                {
                    CollectIndexKeys(item, found);
                }

                break;
            case JObject obj:
                foreach (var member in obj.Properties())
                {
                    if (member.Name == "@context")
                    {
                        CollectIndexTerms(member.Value, found);
                        continue;
                    }

                    if (member.Name == "@index")
                    {
                        found.Add(member);
                    }

                    CollectIndexKeys(member.Value, found);
                }

                break;
        }
    }

    private static void CollectIndexTerms(JToken context, List<JProperty> found)
    {
        switch (context)
        {
            case JArray contexts:
                foreach (var item in contexts)
                {
                    CollectIndexTerms(item, found);
                }

                break;
            case JObject definitions:
                foreach (var term in definitions.Properties().Where(p => !p.Name.StartsWith('@')))
                {
                    if (IsIndexKeyword(term.Value))
                    {
                        found.Add(term);
                    }
                    else if (term.Value is JObject definition)
                    {
                        if (definition.Property("@id") is { } id && IsIndexKeyword(id.Value))
                        {
                            found.Add(id);
                        }

                        if (definition["@context"] is { } scoped)
                        {
                            CollectIndexTerms(scoped, found);
                        }
                    }
                }

                break;
        }
    }

    private static bool IsIndexKeyword(JToken token)
        => token.Type == JTokenType.String && (string)token! == "@index";

    // Deep equality that does not look inside JSON literal payloads, which are opaque data: removing
    // a "@base" key from one, or renaming an "@index" key in it, changes the payload but nothing else.
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
