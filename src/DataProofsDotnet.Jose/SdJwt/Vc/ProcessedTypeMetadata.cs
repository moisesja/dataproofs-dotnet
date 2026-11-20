using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// Type Metadata after full processing (draft-ietf-oauth-sd-jwt-vc-27 §5.7): the <c>vct</c>'s document with its
/// <c>extends</c> chain applied. Claim metadata is merged by <c>path</c>, the child's properties taking precedence
/// (§5.6.5); display metadata is the nearest document's that defines one, never merged (§5.5.2). What is typed here is
/// what -27 defines; a document's other properties are in <see cref="Documents"/>. The contents are the publisher's
/// assertions: -27 §7.8 says not to rely on them unless the publisher is authoritative for the type, §7.6 that
/// every string must be escaped before display, and §7.10 that SVG templates must not run code. Immutable.
/// </summary>
public sealed class ProcessedTypeMetadata
{
    private readonly IReadOnlyList<JsonObject> _documents;

    internal ProcessedTypeMetadata(
        string vct,
        string? name,
        string? description,
        IReadOnlyList<TypeDisplayMetadata> display,
        IReadOnlyList<ClaimMetadata> claims,
        IReadOnlyList<JsonObject> documents)
    {
        Vct = vct;
        Name = name;
        Description = description;
        Display = display;
        Claims = claims;
        _documents = documents;
    }

    /// <summary>The type: the credential's <c>vct</c>, which the first document's <c>vct</c> equals (§5.3).</summary>
    public string Vct { get; }

    /// <summary>The first document's <c>name</c>, for developers (§5.2); <c>null</c> when absent or not a string.</summary>
    public string? Name { get; }

    /// <summary>The first document's <c>description</c>, for developers (§5.2); <c>null</c> when absent or not a string.</summary>
    public string? Description { get; }

    /// <summary>
    /// The effective display metadata, one entry per locale (§5.5), from the nearest document in the chain that defines
    /// <c>display</c> (§5.5.2). Entries without a string <c>locale</c> and <c>name</c> are left out.
    /// </summary>
    public IReadOnlyList<TypeDisplayMetadata> Display { get; }

    /// <summary>
    /// The effective claim metadata (§5.6, §5.6.5): the root type's entries first, in its order, each combined with the
    /// entry of the same <c>path</c> in every extending type, then the entries each extending type adds. The credential
    /// was validated against these.
    /// </summary>
    public IReadOnlyList<ClaimMetadata> Claims { get; }

    /// <summary>The documents processed, as parsed, the <c>vct</c>'s first and each parent after its child. A clone per access.</summary>
    public IReadOnlyList<JsonObject> Documents => [.. _documents.Select(d => (JsonObject)d.DeepClone())];
}

/// <summary>Display metadata for a type in one locale (draft-ietf-oauth-sd-jwt-vc-27 §5.5).</summary>
public sealed class TypeDisplayMetadata
{
    internal TypeDisplayMetadata(string locale, string name, string? description, string? dir, TypeRenderingMetadata? rendering)
    {
        Locale = locale;
        Name = name;
        Description = description;
        Dir = dir;
        Rendering = rendering;
    }

    /// <summary>The language tag (RFC 5646) of this entry.</summary>
    public string Locale { get; }

    /// <summary>The type's name for end users.</summary>
    public string Name { get; }

    /// <summary>The type's description for end users, or <c>null</c>.</summary>
    public string? Description { get; }

    /// <summary>The base text direction, <c>ltr</c>, <c>rtl</c> or <c>auto</c>; <c>null</c> (meaning <c>auto</c>) when absent or another value.</summary>
    public string? Dir { get; }

    /// <summary>The rendering metadata (§5.5.1), or <c>null</c> when absent or not an object.</summary>
    public TypeRenderingMetadata? Rendering { get; }
}

/// <summary>Rendering metadata for a type (draft-ietf-oauth-sd-jwt-vc-27 §5.5.1): one member per supported method.</summary>
public sealed class TypeRenderingMetadata
{
    internal TypeRenderingMetadata(SimpleRenderingMetadata? simple, IReadOnlyList<SvgTemplateMetadata> svgTemplates)
    {
        Simple = simple;
        SvgTemplates = svgTemplates;
    }

    /// <summary>The <c>simple</c> rendering method (§5.5.1.1), or <c>null</c> when absent or not an object.</summary>
    public SimpleRenderingMetadata? Simple { get; }

    /// <summary>The <c>svg_templates</c> rendering method (§5.5.1.2); entries without a string <c>uri</c> are left out.</summary>
    public IReadOnlyList<SvgTemplateMetadata> SvgTemplates { get; }
}

/// <summary>The <c>simple</c> rendering method (draft-ietf-oauth-sd-jwt-vc-27 §5.5.1.1).</summary>
public sealed class SimpleRenderingMetadata
{
    internal SimpleRenderingMetadata(RenderingImageMetadata? logo, RenderingImageMetadata? backgroundImage, string? backgroundColor, string? textColor)
    {
        Logo = logo;
        BackgroundImage = backgroundImage;
        BackgroundColor = backgroundColor;
        TextColor = textColor;
    }

    /// <summary>The logo (§5.5.1.1.1), or <c>null</c>.</summary>
    public RenderingImageMetadata? Logo { get; }

    /// <summary>The background image (§5.5.1.1.2), or <c>null</c>.</summary>
    public RenderingImageMetadata? BackgroundImage { get; }

    /// <summary>The background colour, a CSS RGB colour value as given, or <c>null</c>.</summary>
    public string? BackgroundColor { get; }

    /// <summary>The text colour, a CSS RGB colour value as given, or <c>null</c>.</summary>
    public string? TextColor { get; }
}

/// <summary>A logo or background image of the <c>simple</c> rendering method (draft-ietf-oauth-sd-jwt-vc-27 §5.5.1.1.1, §5.5.1.1.2).</summary>
public sealed class RenderingImageMetadata
{
    internal RenderingImageMetadata(string uri, string? uriIntegrity, string? altText)
    {
        Uri = uri;
        UriIntegrity = uriIntegrity;
        AltText = altText;
    }

    /// <summary>
    /// The image URI, as given: -27 §5.5.1 allows https URLs and <c>data:</c> URIs. The library never retrieves it; a
    /// wallet that does applies §3 and §7.1 and, when <see cref="UriIntegrity"/> is set, checks the bytes with
    /// <see cref="TypeMetadataIntegrity.Matches"/> before use.
    /// </summary>
    public string Uri { get; }

    /// <summary>The <c>uri#integrity</c> value (§6), or <c>null</c>.</summary>
    public string? UriIntegrity { get; }

    /// <summary>The logo's alternative text, or <c>null</c> (always <c>null</c> for a background image).</summary>
    public string? AltText { get; }
}

/// <summary>An SVG template of the <c>svg_templates</c> rendering method (draft-ietf-oauth-sd-jwt-vc-27 §5.5.1.2).</summary>
public sealed class SvgTemplateMetadata
{
    internal SvgTemplateMetadata(string uri, string? uriIntegrity, string? orientation, string? colorScheme, string? contrast)
    {
        Uri = uri;
        UriIntegrity = uriIntegrity;
        Orientation = orientation;
        ColorScheme = colorScheme;
        Contrast = contrast;
    }

    /// <summary>The template URI, as given (see <see cref="RenderingImageMetadata.Uri"/>; §7.10 applies to rendering).</summary>
    public string Uri { get; }

    /// <summary>The <c>uri#integrity</c> value (§6), or <c>null</c>.</summary>
    public string? UriIntegrity { get; }

    /// <summary><c>portrait</c> or <c>landscape</c>; <c>null</c> when absent or another value (§5.5.1.2.1).</summary>
    public string? Orientation { get; }

    /// <summary><c>light</c> or <c>dark</c>; <c>null</c> when absent or another value (§5.5.1.2.1).</summary>
    public string? ColorScheme { get; }

    /// <summary><c>normal</c> or <c>high</c>; <c>null</c> when absent or another value (§5.5.1.2.1).</summary>
    public string? Contrast { get; }
}

/// <summary>Claim metadata after <c>extends</c> processing (draft-ietf-oauth-sd-jwt-vc-27 §5.6, §5.6.5).</summary>
public sealed class ClaimMetadata
{
    internal ClaimMetadata(
        IReadOnlyList<ClaimPathComponent> path,
        IReadOnlyList<ClaimDisplayMetadata> display,
        bool mandatory,
        ClaimSelectiveDisclosure selectiveDisclosure,
        string? svgId)
    {
        Path = path;
        Display = display;
        Mandatory = mandatory;
        SelectiveDisclosure = selectiveDisclosure;
        SvgId = svgId;
    }

    /// <summary>The claim path (§5.6.1): keys, array indices and all-elements selectors, left to right.</summary>
    public IReadOnlyList<ClaimPathComponent> Path { get; }

    /// <summary>The claim's display metadata, one entry per locale (§5.6.2); entries without a string <c>locale</c> and <c>label</c> are left out.</summary>
    public IReadOnlyList<ClaimDisplayMetadata> Display { get; }

    /// <summary>Whether the Issuer must include the claim (§5.6.3); <c>false</c> when omitted.</summary>
    public bool Mandatory { get; }

    /// <summary>Whether the claim must, may or must not be selectively disclosable (§5.6.4); <see cref="ClaimSelectiveDisclosure.Allowed"/> when omitted.</summary>
    public ClaimSelectiveDisclosure SelectiveDisclosure { get; }

    /// <summary>
    /// The SVG placeholder identifier (§5.5.1.2.2), or <c>null</c>. Left out when it breaks §5.6's rules: not only
    /// alphanumerics and underscores, starting with a digit, on a path with a null component, or not unique.
    /// </summary>
    public string? SvgId { get; }
}

/// <summary>One component of a claim path (draft-ietf-oauth-sd-jwt-vc-27 §5.6.1).</summary>
public sealed class ClaimPathComponent
{
    private ClaimPathComponent(string? key, int? index)
    {
        Key = key;
        Index = index;
    }

    internal static ClaimPathComponent ForKey(string key) => new(key, null);

    internal static ClaimPathComponent ForIndex(int index) => new(null, index);

    internal static ClaimPathComponent AllElements { get; } = new(null, null);

    /// <summary>The object key this component selects, or <c>null</c> when it selects array elements.</summary>
    public string? Key { get; }

    /// <summary>The array index this component selects, or <c>null</c>.</summary>
    public int? Index { get; }

    /// <summary>Whether this component is <c>null</c>: every element of the selected arrays.</summary>
    public bool IsAllElements => Key is null && Index is null;

    internal bool SameAs(ClaimPathComponent other)
        => string.Equals(Key, other.Key, StringComparison.Ordinal) && Index == other.Index;

    internal static string Format(IReadOnlyList<ClaimPathComponent> path)
    {
        var node = new JsonArray();
        foreach (var component in path)
            node.Add(component.Key is { } key ? (JsonNode)key : component.Index is { } index ? (JsonNode)index : null);
        return node.ToJsonString();
    }
}

/// <summary>The claim metadata <c>sd</c> values (draft-ietf-oauth-sd-jwt-vc-27 §5.6.4).</summary>
public enum ClaimSelectiveDisclosure
{
    /// <summary><c>allowed</c>, the default: the Issuer may make the claim selectively disclosable.</summary>
    Allowed,

    /// <summary><c>always</c>: the Issuer must make the claim selectively disclosable.</summary>
    Always,

    /// <summary><c>never</c>: the Issuer must not make the claim selectively disclosable.</summary>
    Never,
}

/// <summary>Display metadata for a claim in one locale (draft-ietf-oauth-sd-jwt-vc-27 §5.6.2).</summary>
public sealed class ClaimDisplayMetadata
{
    internal ClaimDisplayMetadata(string locale, string label, string? description, string? dir)
    {
        Locale = locale;
        Label = label;
        Description = description;
        Dir = dir;
    }

    /// <summary>The language tag (RFC 5646) of this entry.</summary>
    public string Locale { get; }

    /// <summary>The claim's label for end users.</summary>
    public string Label { get; }

    /// <summary>The claim's description for end users, or <c>null</c>.</summary>
    public string? Description { get; }

    /// <summary>The base text direction, <c>ltr</c>, <c>rtl</c> or <c>auto</c>; <c>null</c> (meaning <c>auto</c>) when absent or another value.</summary>
    public string? Dir { get; }
}
