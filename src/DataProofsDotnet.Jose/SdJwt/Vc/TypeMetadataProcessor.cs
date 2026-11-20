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

    /// <summary>The outcome of processing: the processed metadata, or a verdict, or a resolver fault.</summary>
    internal sealed class Outcome
    {
        public ProcessedTypeMetadata? Metadata { get; private init; }

        /// <summary>The <c>vct</c>'s own document, as parsed (the raw <c>TypeMetadata</c> result member).</summary>
        public JsonObject? LeafDocument { get; private init; }

        /// <summary>The verdict, a <c>VC_*</c> code and its reason, when processing or validation failed.</summary>
        public string? Error { get; private init; }

        /// <summary>The exception the resolver threw, when it did; <see cref="Error"/> is then the fault's message.</summary>
        public Exception? Fault { get; private init; }

        public static Outcome Success(ProcessedTypeMetadata metadata, JsonObject leaf) => new() { Metadata = metadata, LeafDocument = leaf };

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
                    $"VC_TYPE_METADATA_RESOLVER_FAULT: the Type Metadata resolver failed for '{reference}' ({ex.GetType().Name}); "
                    + "this is a retrieval fault, not a verdict on the credential.",
                    ex);
            }

            if (octets is null)
                return Outcome.Failure(
                    $"VC_TYPE_METADATA_UNAVAILABLE: no Type Metadata document was retrieved for '{reference}', and processing is required ({Revision} §5.7).");

            if (octets.Length > options.MaxDocumentSize)
                return Outcome.Failure(
                    $"VC_TYPE_METADATA_INVALID: the Type Metadata document for '{reference}' is {octets.Length} octets, above the {options.MaxDocumentSize}-octet limit.");

            // §6: "the Consumer verifies that the retrieved document matches it before processing that document".
            if (integrity is not null && TypeMetadataIntegrity.Check(integrity, octets) != TypeMetadataIntegrity.Outcome.Match)
                return Outcome.Failure(
                    $"VC_TYPE_METADATA_INTEGRITY_MISMATCH: the Type Metadata document for '{reference}' does not match '{integrityName}' ({Revision} §6).");

            var (document, parseError) = ParseDocument(octets, reference);
            if (document is null)
                return Outcome.Failure(parseError!);
            documents.Add(document);

            if (document.Extends is not { } parent)
                break;

            if (visited.Contains(parent))
                return Outcome.Failure(
                    $"VC_TYPE_METADATA_EXTENDS_CYCLE: '{reference}' extends '{parent}', which is already in its 'extends' chain ({Revision} §7.4).");

            if (documents.Count > options.MaxExtendsDepth)
                return Outcome.Failure(
                    $"VC_TYPE_METADATA_EXTENDS_DEPTH: the 'extends' chain of '{vct}' is longer than {options.MaxExtendsDepth} hops.");

            reference = parent;
            integrity = document.ExtendsIntegrity;
            integrityName = "extends#integrity";
        }

        // §5.4: each parent is processed before the type that extends it, so merge from the root down.
        var claims = new List<ClaimEntry>();
        IReadOnlyList<TypeDisplayMetadata> display = [];
        for (var i = documents.Count - 1; i >= 0; i--)
        {
            if (Merge(claims, documents[i]) is { } mergeError)
                return Outcome.Failure(mergeError);
            if (documents[i].Display is { } own)
                display = own;
        }

        var effective = Finish(claims);
        var leaf = documents[0];
        var metadata = new ProcessedTypeMetadata(
            vct, ReadString(leaf.Json["name"]), ReadString(leaf.Json["description"]), display, effective,
            [.. documents.Select(d => d.Json)]);

        if (ClaimMetadataValidator.Validate(processedPayload, trace, effective, allDisclosuresPresent) is { } violation)
            return Outcome.Failure(violation);

        return Outcome.Success(metadata, leaf.Json);
    }

    // ------------------------------------------------------------------ parsing

    private sealed class ClaimEntry
    {
        public required IReadOnlyList<ClaimPathComponent> Path { get; init; }

        public bool? Mandatory { get; set; }

        public ClaimSelectiveDisclosure? Sd { get; set; }

        /// <summary>The entry's own display, or <c>null</c> when it defines none (an inherited one then applies).</summary>
        public IReadOnlyList<ClaimDisplayMetadata>? Display { get; set; }

        /// <summary>The entry's own <c>svg_id</c> string, or <c>null</c> when it defines none.</summary>
        public string? SvgId { get; set; }
    }

    private sealed class ParsedDocument
    {
        public required JsonObject Json { get; init; }

        public string? Extends { get; init; }

        public string? ExtendsIntegrity { get; init; }

        public required List<ClaimEntry> Claims { get; init; }

        /// <summary>The document's own display, or <c>null</c> when it defines none (§5.5.2).</summary>
        public IReadOnlyList<TypeDisplayMetadata>? Display { get; init; }
    }

    private static (ParsedDocument? Document, string? Error) ParseDocument(byte[] octets, string reference)
    {
        JsonObject json;
        try
        {
            JoseJson.RequireTranscodableJson(octets, "The Type Metadata document");
            if (JsonNode.Parse(octets, documentOptions: JoseJson.StrictDocument) is not JsonObject parsed)
                return (null, $"VC_TYPE_METADATA_INVALID: the Type Metadata document for '{reference}' is not a JSON object ({Revision} §5.2).");
            json = parsed;
        }
        catch (Exception ex) when (ex is MalformedJoseException or JsonException)
        {
            return (null, $"VC_TYPE_METADATA_INVALID: the Type Metadata document for '{reference}' is not valid JSON ({Revision} §5.2).");
        }

        // §5.3: the document's vct is identical to the reference it was retrieved for. No normalization: a case,
        // trailing-slash or percent-encoding variant names a different type.
        if (!json.TryGetPropertyValue(SdJwtVcConstants.VctClaim, out var vctNode) || ReadString(vctNode) is not { } documentVct)
            return (null, $"VC_TYPE_METADATA_INVALID: the Type Metadata document for '{reference}' has no string 'vct' ({Revision} §5.2).");
        if (!string.Equals(documentVct, reference, StringComparison.Ordinal))
            return (null, $"VC_TYPE_METADATA_VCT_MISMATCH: the Type Metadata document retrieved for '{reference}' describes '{documentVct}' ({Revision} §5.3).");

        string? extends = null;
        string? extendsIntegrity = null;
        if (json.TryGetPropertyValue("extends", out var extendsNode))
        {
            if (ReadString(extendsNode) is not { Length: > 0 } value)
                return (null, $"VC_TYPE_METADATA_INVALID: 'extends' of '{reference}' must be a non-empty string ({Revision} §5.4).");
            extends = value;

            if (json.TryGetPropertyValue("extends#integrity", out var extendsIntegrityNode))
            {
                if (ReadString(extendsIntegrityNode) is not { } integrity)
                    return (null, $"VC_TYPE_METADATA_INTEGRITY_INVALID: 'extends#integrity' of '{reference}' must be an integrity metadata string ({Revision} §6).");
                extendsIntegrity = integrity;
            }
        }

        var claims = new List<ClaimEntry>();
        if (json.TryGetPropertyValue("claims", out var claimsNode))
        {
            if (claimsNode is not JsonArray claimsArray)
                return (null, ClaimMetadataInvalid(reference, "'claims' must be an array of objects"));

            foreach (var item in claimsArray)
            {
                if (item is not JsonObject claim)
                    return (null, ClaimMetadataInvalid(reference, "'claims' must be an array of objects"));
                var (entry, claimError) = ParseClaim(claim);
                if (entry is null)
                    return (null, ClaimMetadataInvalid(reference, claimError!));
                if (claims.Any(c => SamePath(c.Path, entry.Path)))
                    return (null, ClaimMetadataInvalid(reference, $"two claim metadata objects have the path {ClaimPathComponent.Format(entry.Path)}"));
                claims.Add(entry);
            }
        }

        return (new ParsedDocument
        {
            Json = json,
            Extends = extends,
            ExtendsIntegrity = extendsIntegrity,
            Claims = claims,
            Display = json["display"] is JsonArray displayArray ? ParseTypeDisplay(displayArray) : null,
        }, null);
    }

    private static string ClaimMetadataInvalid(string reference, string reason)
        => $"VC_CLAIM_METADATA_INVALID: in the Type Metadata of '{reference}', {reason} ({Revision} §5.6).";

    private static (ClaimEntry? Entry, string? Error) ParseClaim(JsonObject claim)
    {
        // §5.6.1: "a non-empty array of strings, null values, or non-negative integers".
        if (!claim.TryGetPropertyValue("path", out var pathNode) || pathNode is not JsonArray { Count: > 0 } pathArray)
            return (null, "a claim metadata object's 'path' must be a non-empty array");

        var path = new List<ClaimPathComponent>(pathArray.Count);
        foreach (var component in pathArray)
        {
            switch (component)
            {
                case null:
                    path.Add(ClaimPathComponent.AllElements);
                    break;
                case JsonValue value when value.GetValueKind() == JsonValueKind.String:
                    path.Add(ClaimPathComponent.ForKey(value.GetValue<string>()));
                    break;
                case JsonValue value when value.GetValueKind() == JsonValueKind.Number && value.TryGetValue<int>(out var index) && index >= 0:
                    path.Add(ClaimPathComponent.ForIndex(index));
                    break;
                default:
                    return (null, $"a path component must be a string, null or a non-negative integer; found {component.ToJsonString()}");
            }
        }

        var entry = new ClaimEntry { Path = path };

        // §5.6.3: a boolean. §5.6.4: one of three strings.
        if (claim.TryGetPropertyValue("mandatory", out var mandatoryNode))
        {
            if (mandatoryNode?.GetValueKind() is not (JsonValueKind.True or JsonValueKind.False))
                return (null, $"'mandatory' of {ClaimPathComponent.Format(path)} must be a boolean");
            entry.Mandatory = mandatoryNode.GetValueKind() == JsonValueKind.True;
        }

        if (claim.TryGetPropertyValue("sd", out var sdNode))
        {
            entry.Sd = ReadString(sdNode) switch
            {
                "always" => ClaimSelectiveDisclosure.Always,
                "allowed" => ClaimSelectiveDisclosure.Allowed,
                "never" => ClaimSelectiveDisclosure.Never,
                _ => null,
            };
            if (entry.Sd is null)
                return (null, $"'sd' of {ClaimPathComponent.Format(path)} must be \"always\", \"allowed\" or \"never\"");
        }

        // Display and svg_id never fail processing (§5.6, the -21 narrowing): a malformed one is not understood and ignored.
        if (claim["display"] is JsonArray displayArray)
            entry.Display = ParseClaimDisplay(displayArray);
        if (ReadString(claim["svg_id"]) is { } svgId)
            entry.SvgId = svgId;

        return (entry, null);
    }

    private static List<TypeDisplayMetadata> ParseTypeDisplay(JsonArray array)
    {
        var result = new List<TypeDisplayMetadata>();
        foreach (var item in array)
        {
            if (item is not JsonObject entry || ReadString(entry["locale"]) is not { } locale || ReadString(entry["name"]) is not { } name)
                continue;
            result.Add(new TypeDisplayMetadata(
                locale, name, ReadString(entry["description"]), ReadDir(entry["dir"]),
                entry["rendering"] is JsonObject rendering ? ParseRendering(rendering) : null));
        }
        return result;
    }

    private static TypeRenderingMetadata ParseRendering(JsonObject rendering)
    {
        SimpleRenderingMetadata? simple = null;
        if (rendering["simple"] is JsonObject s)
        {
            simple = new SimpleRenderingMetadata(
                ParseImage(s["logo"], withAltText: true),
                ParseImage(s["background_image"], withAltText: false),
                ReadString(s["background_color"]),
                ReadString(s["text_color"]));
        }

        var templates = new List<SvgTemplateMetadata>();
        if (rendering["svg_templates"] is JsonArray svgTemplates)
        {
            foreach (var item in svgTemplates)
            {
                if (item is not JsonObject template || ReadString(template["uri"]) is not { } uri)
                    continue;
                var properties = template["properties"] as JsonObject;
                templates.Add(new SvgTemplateMetadata(
                    uri,
                    ReadString(template["uri#integrity"]),
                    OneOf(properties?["orientation"], "portrait", "landscape"),
                    OneOf(properties?["color_scheme"], "light", "dark"),
                    OneOf(properties?["contrast"], "normal", "high")));
            }
        }

        return new TypeRenderingMetadata(simple, templates);
    }

    private static RenderingImageMetadata? ParseImage(JsonNode? node, bool withAltText)
        => node is JsonObject image && ReadString(image["uri"]) is { } uri
            ? new RenderingImageMetadata(uri, ReadString(image["uri#integrity"]), withAltText ? ReadString(image["alt_text"]) : null)
            : null;

    private static List<ClaimDisplayMetadata> ParseClaimDisplay(JsonArray array)
    {
        var result = new List<ClaimDisplayMetadata>();
        foreach (var item in array)
        {
            if (item is not JsonObject entry || ReadString(entry["locale"]) is not { } locale || ReadString(entry["label"]) is not { } label)
                continue;
            result.Add(new ClaimDisplayMetadata(locale, label, ReadString(entry["description"]), ReadDir(entry["dir"])));
        }
        return result;
    }

    private static string? ReadDir(JsonNode? node) => OneOf(node, "ltr", "rtl", "auto");

    private static string? OneOf(JsonNode? node, params string[] allowed)
        => ReadString(node) is { } value && allowed.Contains(value, StringComparer.Ordinal) ? value : null;

    /// <summary>A JSON string's value, or <c>null</c> for anything else, including a string that is not text.</summary>
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

    private static bool SamePath(IReadOnlyList<ClaimPathComponent> a, IReadOnlyList<ClaimPathComponent> b)
        => a.Count == b.Count && a.Zip(b).All(pair => pair.First.SameAs(pair.Second));

    /// <summary>
    /// Applies one document's claim metadata over the effective claim metadata of the types it extends (§5.6.5): an entry
    /// with the same path is combined, the child's properties taking precedence within the limits of §5.6.5.1; any other
    /// entry is appended.
    /// </summary>
    private static string? Merge(List<ClaimEntry> effective, ParsedDocument document)
    {
        var reference = ReadString(document.Json[SdJwtVcConstants.VctClaim]);
        foreach (var child in document.Claims)
        {
            var parent = effective.FirstOrDefault(e => SamePath(e.Path, child.Path));
            if (parent is null)
            {
                effective.Add(new ClaimEntry
                {
                    Path = child.Path, Mandatory = child.Mandatory, Sd = child.Sd, Display = child.Display, SvgId = child.SvgId,
                });
                continue;
            }

            var path = ClaimPathComponent.Format(child.Path);
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
