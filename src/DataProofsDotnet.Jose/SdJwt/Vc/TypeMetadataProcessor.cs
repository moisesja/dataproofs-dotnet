using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Json;

namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// Type Metadata processing (draft-ietf-oauth-sd-jwt-vc-27 §5.7), shared by <see cref="SdJwtVcVerifier"/> and
/// <see cref="SdJwtVcIssuer"/> so both apply the same rules: retrieve the <c>vct</c>'s document and every <c>extends</c>
/// parent through the caller's resolver, check each against its integrity value before parsing it (§6), require its
/// <c>vct</c> to be identical to the reference it was retrieved for (§5.3), refuse cycles (§7.4) and chains longer than
/// the configured depth, then merge from the root down (§5.5.2, §5.6.5) and validate the credential's processed payload
/// against the merged claim metadata (<see cref="ClaimMetadataValidator"/>).
/// </summary>
internal static class TypeMetadataProcessor
{
    private const string Revision = SdJwtVcConstants.Revision;

    /// <summary>
    /// The most entries processing turns into objects across one <c>extends</c> chain: claim metadata objects, path
    /// components, and display, claim display and SVG template entries. The octet and depth bounds limit a document's
    /// size, not how many of these it holds, and each costs a few hundred bytes once typed, so a 1 MiB document of
    /// two-octet path components cost about 100 MB (adversarial pass 3). A rich real type (dozens of claims, each with
    /// display in every EU language) holds a few thousand. Claims and path components, which must all be well formed,
    /// are counted from the parsed array lengths before any is read; display and template entries one by one, after
    /// their required string members are checked and before they are built, since an entry without them is skipped
    /// unbuilt and a malformed display never rejects (-21, -27 §5.6). A
    /// chain past the bound fails with <c>VC_TYPE_METADATA_INVALID</c>, since processing that is required and cannot
    /// complete rejects (-27 §5.7).
    /// </summary>
    internal const int EntryBudget = 10_000;

    /// <summary>The most characters of a document value an error message repeats; the rest is elided.</summary>
    internal const int EchoLength = 120;

    /// <summary><paramref name="value"/>, cut to <see cref="EchoLength"/> characters for an error message.</summary>
    internal static string Echo(string value)
    {
        if (value.Length <= EchoLength)
            return value;
        var cut = char.IsHighSurrogate(value[EchoLength - 1]) ? EchoLength - 1 : EchoLength;
        return string.Concat(value.AsSpan(0, cut), $"... ({value.Length} characters)");
    }

    private sealed class Entries
    {
        private int _remaining = EntryBudget;

        public bool Spend(int count)
        {
            _remaining -= count;
            return _remaining >= 0;
        }
    }

    /// <summary>The outcome of processing: the processed metadata, or a verdict, or a resolver fault.</summary>
    internal sealed class Outcome
    {
        public ProcessedTypeMetadata? Metadata { get; private init; }

        /// <summary>The octets of the <c>vct</c>'s own document (the raw <c>TypeMetadata</c> result member parses them).</summary>
        public byte[]? LeafOctets { get; private init; }

        /// <summary>The verdict, a <c>VC_*</c> code and its reason, when processing or validation failed.</summary>
        public string? Error { get; private init; }

        /// <summary>The exception the resolver threw, when it did; <see cref="Error"/> is then the fault's message.</summary>
        public Exception? Fault { get; private init; }

        public static Outcome Success(ProcessedTypeMetadata metadata, byte[] leaf) => new() { Metadata = metadata, LeafOctets = leaf };

        public static Outcome Failure(string error) => new() { Error = error };

        public static Outcome Faulted(string error, Exception fault) => new() { Error = error, Fault = fault };
    }

    /// <summary>
    /// Processes the Type Metadata of the credential whose issuer-signed payload is <paramref name="signedPayload"/>,
    /// and validates <paramref name="processedPayload"/> against its claim metadata.
    /// </summary>
    /// <param name="signedPayload">The issuer-signed payload; its clear <c>vct</c> and <c>vct#integrity</c> are read.</param>
    /// <param name="processedPayload">The payload the same reconstruction as <paramref name="trace"/> returned.</param>
    /// <param name="trace">Where each part of <paramref name="processedPayload"/> came from.</param>
    /// <param name="allDisclosuresPresent">
    /// <c>true</c> at issuance, where every Disclosure is present and an unresolved digest can only be a decoy.
    /// </param>
    /// <param name="options">The caller's processing options.</param>
    /// <param name="cancellationToken">Cancels retrieval; a cancellation of this token propagates.</param>
    public static async Task<Outcome> ProcessAsync(
        JsonObject signedPayload,
        JsonObject processedPayload,
        ReconstructionTrace trace,
        bool allDisclosuresPresent,
        TypeMetadataProcessingOptions options,
        CancellationToken cancellationToken)
    {
        if (!signedPayload.TryGetPropertyValue(SdJwtVcConstants.VctClaim, out var vctNode)
            || SdJwtVcClaimRules.ReadTypeValue(vctNode) is not { } vct)
        {
            return Outcome.Failure($"VC_VCT_MISSING: SD-JWT VC payload has no non-empty string 'vct' claim ({Revision} §2.2.2.1).");
        }

        string? integrity = null;
        if (signedPayload.TryGetPropertyValue(SdJwtVcConstants.VctIntegrityClaim, out var integrityNode))
        {
            if (ReadString(integrityNode) is not { } value)
                return Outcome.Failure(
                    $"VC_TYPE_METADATA_INTEGRITY_INVALID: the 'vct#integrity' claim must be an integrity metadata string ({Revision} §5.3, §6).");
            integrity = value;
        }

        var documents = new List<ParsedDocument>();
        var entries = new Entries();
        var visited = new HashSet<string>(StringComparer.Ordinal);
        var reference = vct;
        var integrityName = SdJwtVcConstants.VctIntegrityClaim;
        while (true)
        {
            visited.Add(reference);

            // A malformed integrity value is refused before anything is retrieved: no retrieval could satisfy it.
            if (integrity is not null && TypeMetadataIntegrity.Check(integrity, []) is var syntax
                and (TypeMetadataIntegrity.Outcome.Malformed or TypeMetadataIntegrity.Outcome.Unsupported))
            {
                return Outcome.Failure(
                    $"VC_TYPE_METADATA_INTEGRITY_INVALID: '{integrityName}' "
                    + (syntax == TypeMetadataIntegrity.Outcome.Malformed
                        ? "is not a well-formed integrity metadata string"
                        : "names no supported hash algorithm (sha256, sha384, sha512)")
                    + $" ({Revision} §6).");
            }

            byte[]? octets;
            try
            {
                octets = await options.Resolver.ResolveDocumentAsync(reference, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                return Outcome.Faulted(
                    $"VC_TYPE_METADATA_RESOLVER_FAULT: the Type Metadata resolver failed for '{Echo(reference)}' ({ex.GetType().Name}); "
                    + "this is a retrieval fault, not a verdict on the credential.",
                    ex);
            }

            if (octets is null)
                return Outcome.Failure(
                    $"VC_TYPE_METADATA_UNAVAILABLE: no Type Metadata document was retrieved for '{Echo(reference)}', and processing is required ({Revision} §5.7).");

            if (octets.Length > options.MaxDocumentSize)
                return Outcome.Failure(
                    $"VC_TYPE_METADATA_INVALID: the Type Metadata document for '{Echo(reference)}' is {octets.Length} octets, above the {options.MaxDocumentSize}-octet limit.");

            // One copy, taken before anything reads it, so the octets hashed are the octets parsed even if the resolver
            // keeps writing to the buffer it returned (a pooled or refreshed buffer).
            octets = octets.ToArray();

            // §6: "the Consumer verifies that the retrieved document matches it before processing that document".
            if (integrity is not null && TypeMetadataIntegrity.Check(integrity, octets) != TypeMetadataIntegrity.Outcome.Match)
                return Outcome.Failure(
                    $"VC_TYPE_METADATA_INTEGRITY_MISMATCH: the Type Metadata document for '{Echo(reference)}' does not match '{integrityName}' ({Revision} §6).");

            var (document, parseError) = ParseDocument(octets, reference, entries);
            if (document is null)
                return Outcome.Failure(parseError!);
            documents.Add(document);

            if (document.Extends is not { } parent)
                break;

            if (visited.Contains(parent))
                return Outcome.Failure(
                    $"VC_TYPE_METADATA_EXTENDS_CYCLE: '{Echo(reference)}' extends '{Echo(parent)}', which is already in its 'extends' chain ({Revision} §7.4).");

            if (documents.Count > options.MaxExtendsDepth)
                return Outcome.Failure(
                    $"VC_TYPE_METADATA_EXTENDS_DEPTH: the 'extends' chain of '{Echo(vct)}' is longer than {options.MaxExtendsDepth} hops.");

            reference = parent;
            integrity = document.ExtendsIntegrity;
            integrityName = "extends#integrity";
        }

        // §5.4: each parent is processed before the type that extends it, so merge from the root down.
        var claims = new List<ClaimEntry>();
        var byKey = new Dictionary<string, ClaimEntry>(StringComparer.Ordinal);
        IReadOnlyList<TypeDisplayMetadata> display = [];
        for (var i = documents.Count - 1; i >= 0; i--)
        {
            if (Merge(claims, byKey, documents[i]) is { } mergeError)
                return Outcome.Failure(mergeError);
            if (documents[i].Display is { } own)
                display = own;
        }

        var effective = Finish(claims);
        var leaf = documents[0];
        var metadata = new ProcessedTypeMetadata(
            vct, leaf.Name, leaf.Description, display, effective, [.. documents.Select(d => d.Octets)]);

        if (ClaimMetadataValidator.Validate(processedPayload, trace, effective, allDisclosuresPresent) is { } violation)
            return Outcome.Failure(violation);

        return Outcome.Success(metadata, leaf.Octets);
    }

    // ------------------------------------------------------------------ parsing

    private sealed class ClaimEntry
    {
        public required IReadOnlyList<ClaimPathComponent> Path { get; init; }

        /// <summary>The path's canonical key (<see cref="ClaimPathComponent.CanonicalKey"/>): equal paths, and only equal paths, share it.</summary>
        public required string Key { get; init; }

        public bool? Mandatory { get; set; }

        public ClaimSelectiveDisclosure? Sd { get; set; }

        /// <summary>The entry's own display, or <c>null</c> when it defines none (an inherited one then applies).</summary>
        public IReadOnlyList<ClaimDisplayMetadata>? Display { get; set; }

        /// <summary>The entry's own <c>svg_id</c> string, or <c>null</c> when it defines none.</summary>
        public string? SvgId { get; set; }
    }

    private sealed class ParsedDocument
    {
        /// <summary>The octets as retrieved and checked: what the result keeps, parsed again on access.</summary>
        public required byte[] Octets { get; init; }

        public required string Vct { get; init; }

        public string? Name { get; init; }

        public string? Description { get; init; }

        public string? Extends { get; init; }

        public string? ExtendsIntegrity { get; init; }

        public required List<ClaimEntry> Claims { get; init; }

        /// <summary>The document's own display, or <c>null</c> when it defines none (§5.5.2).</summary>
        public IReadOnlyList<TypeDisplayMetadata>? Display { get; init; }
    }

    /// <summary>
    /// Reads one document. It is parsed into a <see cref="JsonDocument"/> and read through <see cref="JsonElement"/>, so
    /// nothing is built for what processing does not read, and array lengths are charged to <paramref name="entries"/>
    /// before their elements are read. Only the typed result and the octets outlive the call.
    /// </summary>
    private static (ParsedDocument? Document, string? Error) ParseDocument(byte[] octets, string reference, Entries entries)
    {
        try
        {
            JoseJson.RequireTranscodableJson(octets, "The Type Metadata document");
            using var parsed = JsonDocument.Parse(octets, JoseJson.StrictDocument);
            return ReadDocument(parsed.RootElement, octets, reference, entries);
        }
        catch (Exception ex) when (ex is MalformedJoseException or JsonException)
        {
            return (null, $"VC_TYPE_METADATA_INVALID: the Type Metadata document for '{Echo(reference)}' is not valid JSON ({Revision} §5.2).");
        }
    }

    private static (ParsedDocument? Document, string? Error) ReadDocument(JsonElement json, byte[] octets, string reference, Entries entries)
    {
        if (json.ValueKind != JsonValueKind.Object)
            return (null, $"VC_TYPE_METADATA_INVALID: the Type Metadata document for '{Echo(reference)}' is not a JSON object ({Revision} §5.2).");

        // §5.3: the document's vct is identical to the reference it was retrieved for. No normalization: a case,
        // trailing-slash or percent-encoding variant names a different type.
        if (ReadString(json, SdJwtVcConstants.VctClaim) is not { } documentVct)
            return (null, $"VC_TYPE_METADATA_INVALID: the Type Metadata document for '{Echo(reference)}' has no string 'vct' ({Revision} §5.2).");
        if (!string.Equals(documentVct, reference, StringComparison.Ordinal))
            return (null, $"VC_TYPE_METADATA_VCT_MISMATCH: the Type Metadata document retrieved for '{Echo(reference)}' describes '{Echo(documentVct)}' ({Revision} §5.3).");

        string? extends = null;
        string? extendsIntegrity = null;
        if (json.TryGetProperty("extends", out var extendsElement))
        {
            if (ReadString(extendsElement) is not { Length: > 0 } value)
                return (null, $"VC_TYPE_METADATA_INVALID: 'extends' of '{Echo(reference)}' must be a non-empty string ({Revision} §5.4).");
            extends = value;

            if (json.TryGetProperty("extends#integrity", out var extendsIntegrityElement))
            {
                if (ReadString(extendsIntegrityElement) is not { } integrity)
                    return (null, $"VC_TYPE_METADATA_INTEGRITY_INVALID: 'extends#integrity' of '{Echo(reference)}' must be an integrity metadata string ({Revision} §6).");
                extendsIntegrity = integrity;
            }
        }

        var claims = new List<ClaimEntry>();
        if (json.TryGetProperty("claims", out var claimsElement))
        {
            if (claimsElement.ValueKind != JsonValueKind.Array)
                return (null, ClaimMetadataInvalid(reference, "'claims' must be an array of objects"));
            // Charged up front, before any element is checked, and that is safe: every element must be a well-formed
            // claim metadata object (§5.6), so an element that would not be kept fails the document anyway, and the
            // charge only decides which refusal is reported. Charging first means nothing is built for a chain that
            // is over the bound.
            if (!entries.Spend(claimsElement.GetArrayLength()))
                return (null, TooManyEntries(reference));

            var keys = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in claimsElement.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object)
                    return (null, ClaimMetadataInvalid(reference, "'claims' must be an array of objects"));
                var (entry, claimError) = ParseClaim(item, entries);
                if (entry is null)
                    return (null, claimError == TooManyEntriesMarker ? TooManyEntries(reference) : ClaimMetadataInvalid(reference, claimError!));
                if (!keys.Add(entry.Key))
                    return (null, ClaimMetadataInvalid(reference, $"two claim metadata objects have the path {ClaimPathComponent.Describe(entry.Path)}"));
                claims.Add(entry);
            }
        }

        IReadOnlyList<TypeDisplayMetadata>? display = null;
        if (json.TryGetProperty("display", out var displayElement) && displayElement.ValueKind == JsonValueKind.Array)
        {
            display = ParseTypeDisplay(displayElement, entries);
            if (display is null)
                return (null, TooManyEntries(reference));
        }

        return (new ParsedDocument
        {
            Octets = octets,
            Vct = documentVct,
            Name = ReadString(json, "name"),
            Description = ReadString(json, "description"),
            Extends = extends,
            ExtendsIntegrity = extendsIntegrity,
            Claims = claims,
            Display = display,
        }, null);
    }

    private const string TooManyEntriesMarker = "\0entries";

    private static string TooManyEntries(string reference)
        => $"VC_TYPE_METADATA_INVALID: the Type Metadata chain reaching '{Echo(reference)}' holds more than {EntryBudget} claim, path, "
            + $"display and template entries, so it cannot be processed ({Revision} §5.7).";

    private static string ClaimMetadataInvalid(string reference, string reason)
        => $"VC_CLAIM_METADATA_INVALID: in the Type Metadata of '{Echo(reference)}', {reason} ({Revision} §5.6).";

    private static (ClaimEntry? Entry, string? Error) ParseClaim(JsonElement claim, Entries entries)
    {
        // §5.6.1: "a non-empty array of strings, null values, or non-negative integers".
        if (!claim.TryGetProperty("path", out var pathElement) || pathElement.ValueKind != JsonValueKind.Array || pathElement.GetArrayLength() == 0)
            return (null, "a claim metadata object's 'path' must be a non-empty array");
        // Up front for the same reason as the claims: every component must be valid or the document fails (§5.6.1).
        if (!entries.Spend(pathElement.GetArrayLength()))
            return (null, TooManyEntriesMarker);

        var path = new List<ClaimPathComponent>(pathElement.GetArrayLength());
        foreach (var component in pathElement.EnumerateArray())
        {
            switch (component.ValueKind)
            {
                case JsonValueKind.Null:
                    path.Add(ClaimPathComponent.AllElements);
                    break;
                case JsonValueKind.String when ReadString(component) is { } key:
                    path.Add(ClaimPathComponent.ForKey(key));
                    break;
                case JsonValueKind.Number when component.TryGetInt32(out var index) && index >= 0:
                    path.Add(ClaimPathComponent.ForIndex(index));
                    break;
                default:
                    return (null, $"a path component must be a string, null or a non-negative integer; found a {Kind(component)}");
            }
        }

        var entry = new ClaimEntry { Path = path, Key = ClaimPathComponent.CanonicalKey(path) };

        // §5.6.3: a boolean. §5.6.4: one of three strings.
        if (claim.TryGetProperty("mandatory", out var mandatory))
        {
            if (mandatory.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                return (null, $"'mandatory' of {ClaimPathComponent.Describe(path)} must be a boolean");
            entry.Mandatory = mandatory.ValueKind == JsonValueKind.True;
        }

        if (claim.TryGetProperty("sd", out var sd))
        {
            entry.Sd = ReadString(sd) switch
            {
                "always" => ClaimSelectiveDisclosure.Always,
                "allowed" => ClaimSelectiveDisclosure.Allowed,
                "never" => ClaimSelectiveDisclosure.Never,
                _ => null,
            };
            if (entry.Sd is null)
                return (null, $"'sd' of {ClaimPathComponent.Describe(path)} must be \"always\", \"allowed\" or \"never\"");
        }

        // Display and svg_id never fail processing (§5.6, the -21 narrowing): a malformed one is not understood and ignored.
        if (claim.TryGetProperty("display", out var display) && display.ValueKind == JsonValueKind.Array)
        {
            entry.Display = ParseClaimDisplay(display, entries);
            if (entry.Display is null)
                return (null, TooManyEntriesMarker);
        }
        if (ReadString(claim, "svg_id") is { } svgId)
            entry.SvgId = svgId;

        return (entry, null);
    }

    private static string Kind(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Number => "number that is not a non-negative 32-bit integer",
        JsonValueKind.True or JsonValueKind.False => "boolean",
        JsonValueKind.Object => "object",
        JsonValueKind.Array => "array",
        _ => "value of another kind",
    };

    /// <returns>The entries, or <c>null</c> when they exceed <see cref="EntryBudget"/>.</returns>
    private static List<TypeDisplayMetadata>? ParseTypeDisplay(JsonElement array, Entries entries)
    {
        // Charged per entry kept, after its required members are checked and before it is built: an element that is not an
        // object, or lacks a string locale and name, is skipped unbuilt and uncharged (its rendering is not read either),
        // so a malformed display costs no more than its octets and never rejects (-21, -27 §5.6).
        var result = new List<TypeDisplayMetadata>();
        foreach (var entry in array.EnumerateArray())
        {
            if (!HasStrings(entry, "locale", "name"))
                continue;
            if (!entries.Spend(1))
                return null;
            if (ReadString(entry, "locale") is not { } locale || ReadString(entry, "name") is not { } name)
                continue; // Unreachable: the document passed the transcodable-JSON check, so every string reads.
            TypeRenderingMetadata? rendering = null;
            if (entry.TryGetProperty("rendering", out var renderingElement) && renderingElement.ValueKind == JsonValueKind.Object)
            {
                rendering = ParseRendering(renderingElement, entries);
                if (rendering is null)
                    return null;
            }
            result.Add(new TypeDisplayMetadata(locale, name, ReadString(entry, "description"), ReadDir(entry), rendering));
        }
        return result;
    }

    private static TypeRenderingMetadata? ParseRendering(JsonElement rendering, Entries entries)
    {
        SimpleRenderingMetadata? simple = null;
        if (rendering.TryGetProperty("simple", out var s) && s.ValueKind == JsonValueKind.Object)
        {
            simple = new SimpleRenderingMetadata(
                ParseImage(s, "logo", withAltText: true),
                ParseImage(s, "background_image", withAltText: false),
                ReadString(s, "background_color"),
                ReadString(s, "text_color"));
        }

        var templates = new List<SvgTemplateMetadata>();
        if (rendering.TryGetProperty("svg_templates", out var svgTemplates) && svgTemplates.ValueKind == JsonValueKind.Array)
        {
            foreach (var template in svgTemplates.EnumerateArray())
            {
                // Checked, then charged, then built, as for a display entry.
                if (!HasStrings(template, "uri"))
                    continue;
                if (!entries.Spend(1))
                    return null;
                if (ReadString(template, "uri") is not { } uri)
                    continue; // Unreachable, as above.
                var properties = template.TryGetProperty("properties", out var p) && p.ValueKind == JsonValueKind.Object ? p : default;
                templates.Add(new SvgTemplateMetadata(
                    uri,
                    ReadString(template, "uri#integrity"),
                    OneOf(properties, "orientation", "portrait", "landscape"),
                    OneOf(properties, "color_scheme", "light", "dark"),
                    OneOf(properties, "contrast", "normal", "high")));
            }
        }

        return new TypeRenderingMetadata(simple, templates);
    }

    private static RenderingImageMetadata? ParseImage(JsonElement simple, string name, bool withAltText)
        => simple.TryGetProperty(name, out var image) && image.ValueKind == JsonValueKind.Object && ReadString(image, "uri") is { } uri
            ? new RenderingImageMetadata(uri, ReadString(image, "uri#integrity"), withAltText ? ReadString(image, "alt_text") : null)
            : null;

    /// <returns>The entries, or <c>null</c> when they exceed <see cref="EntryBudget"/>.</returns>
    private static List<ClaimDisplayMetadata>? ParseClaimDisplay(JsonElement array, Entries entries)
    {
        // Checked, then charged, then built, as for a type display entry.
        var result = new List<ClaimDisplayMetadata>();
        foreach (var entry in array.EnumerateArray())
        {
            if (!HasStrings(entry, "locale", "label"))
                continue;
            if (!entries.Spend(1))
                return null;
            if (ReadString(entry, "locale") is not { } locale || ReadString(entry, "label") is not { } label)
                continue; // Unreachable, as above.
            result.Add(new ClaimDisplayMetadata(locale, label, ReadString(entry, "description"), ReadDir(entry)));
        }
        return result;
    }

    private static string? ReadDir(JsonElement entry) => OneOf(entry, "dir", "ltr", "rtl", "auto");

    /// <summary>Whether <paramref name="obj"/> is an object whose <paramref name="names"/> are all JSON strings, read without allocating.</summary>
    private static bool HasStrings(JsonElement obj, params string[] names)
    {
        if (obj.ValueKind != JsonValueKind.Object)
            return false;
        foreach (var name in names)
        {
            if (!obj.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
                return false;
        }
        return true;
    }

    /// <summary>Member <paramref name="name"/> when it is one of <paramref name="allowed"/>, compared without reading a longer string.</summary>
    private static string? OneOf(JsonElement obj, string name, params string[] allowed)
    {
        if (obj.ValueKind != JsonValueKind.Object || !obj.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
            return null;
        foreach (var candidate in allowed)
        {
            if (value.ValueEquals(candidate))
                return candidate;
        }
        return null;
    }

    /// <summary>Member <paramref name="name"/> of <paramref name="obj"/> when it is a JSON string, or <c>null</c>.</summary>
    private static string? ReadString(JsonElement obj, string name)
        => obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out var value) ? ReadString(value) : null;

    /// <summary>A JSON string's value, or <c>null</c> for anything else, including a string that is not text.</summary>
    private static string? ReadString(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.String)
            return null;
        try
        {
            return element.GetString();
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>A <see cref="JsonNode"/> string's value (the credential's claims), or <c>null</c>.</summary>
    private static string? ReadString(JsonNode? node)
    {
        if (node is not JsonValue value || value.GetValueKind() != JsonValueKind.String)
            return null;
        try
        {
            return value.GetValue<string>();
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    // ------------------------------------------------------------------ merging

    /// <summary>
    /// Applies one document's claim metadata over the effective claim metadata of the types it extends (§5.6.5): an entry
    /// with the same path is combined, the child's properties taking precedence within the limits of §5.6.5.1; any other
    /// entry is appended.
    /// </summary>
    private static string? Merge(List<ClaimEntry> effective, Dictionary<string, ClaimEntry> byKey, ParsedDocument document)
    {
        var reference = Echo(document.Vct);
        foreach (var child in document.Claims)
        {
            if (!byKey.TryGetValue(child.Key, out var parent))
            {
                var added = new ClaimEntry
                {
                    Path = child.Path, Key = child.Key, Mandatory = child.Mandatory, Sd = child.Sd, Display = child.Display, SvgId = child.SvgId,
                };
                effective.Add(added);
                byKey.Add(added.Key, added);
                continue;
            }

            var path = ClaimPathComponent.Describe(child.Path);
            if (parent.Sd is (ClaimSelectiveDisclosure.Always or ClaimSelectiveDisclosure.Never) && child.Sd is { } sd && sd != parent.Sd)
                return $"VC_CLAIM_METADATA_OVERRIDE_INVALID: '{reference}' changes 'sd' of {path} from {Name(parent.Sd.Value)} to {Name(sd)}; "
                    + $"an extending type MUST NOT change always or never ({Revision} §5.6.5.1).";
            if (parent.Mandatory == true && child.Mandatory == false)
                return $"VC_CLAIM_METADATA_OVERRIDE_INVALID: '{reference}' makes the mandatory claim {path} optional ({Revision} §5.6.5.1).";

            parent.Sd = child.Sd ?? parent.Sd;
            parent.Mandatory = child.Mandatory ?? parent.Mandatory;
            parent.Display = child.Display ?? parent.Display;
            parent.SvgId = child.SvgId ?? parent.SvgId;
        }
        return null;
    }

    private static string Name(ClaimSelectiveDisclosure sd) => sd switch
    {
        ClaimSelectiveDisclosure.Always => "always",
        ClaimSelectiveDisclosure.Never => "never",
        _ => "allowed",
    };

    /// <summary>The effective entries, typed, with each <c>svg_id</c> kept only where §5.6 allows it.</summary>
    private static List<ClaimMetadata> Finish(List<ClaimEntry> entries)
    {
        var counts = entries.Where(e => e.SvgId is not null)
            .GroupBy(e => e.SvgId!, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);

        return [.. entries.Select(e => new ClaimMetadata(
            e.Path,
            e.Display ?? [],
            e.Mandatory ?? false,
            e.Sd ?? ClaimSelectiveDisclosure.Allowed,
            e.SvgId is { } svgId && counts[svgId] == 1 && IsSvgId(svgId) && !e.Path.Any(c => c.IsAllElements) ? svgId : null))];
    }

    /// <summary>§5.6: "only alphanumeric characters and underscores and MUST NOT start with a digit".</summary>
    private static bool IsSvgId(string value)
        => value.Length > 0 && !char.IsAsciiDigit(value[0]) && value.All(c => char.IsAsciiLetterOrDigit(c) || c == '_');
}
