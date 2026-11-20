using System.Globalization;
using System.Text;

namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// Where a presented Disclosure was resolved during reconstruction (RFC 9901 §7.1): the claim path of the value it
/// discloses in the processed payload, from the top-level object down. The path has the concrete form of an SD-JWT VC
/// claim path (draft-ietf-oauth-sd-jwt-vc-27 §5.6.1): a member name for each object level and an index for each array
/// level. An index counts elements of the processed array, so withheld or decoy elements are not counted.
/// </summary>
/// <param name="Disclosure">The presented Disclosure.</param>
/// <param name="Path">
/// The claim path. It is never empty, and its first component is always a member name: the top-level claim the
/// Disclosure is, or sits inside.
/// </param>
internal sealed record DisclosurePosition(Disclosure Disclosure, IReadOnlyList<ClaimPathComponent> Path)
{
    /// <summary>The top-level claim this Disclosure is, or sits inside.</summary>
    public string TopLevelClaim => Path[0].Name!;

    /// <summary>The path in dotted form for messages, with array indices in brackets: <c>status.lists[0].idx</c>.</summary>
    public override string ToString()
    {
        var text = new StringBuilder();
        foreach (var component in Path)
        {
            if (component.Name is { } name)
                text.Append(text.Length == 0 ? string.Empty : ".").Append(name);
            else
                text.Append('[').Append(component.Index.ToString(CultureInfo.InvariantCulture)).Append(']');
        }
        return text.ToString();
    }
}

/// <summary>One component of a <see cref="DisclosurePosition"/> path: an object member name, or an array index.</summary>
internal readonly record struct ClaimPathComponent
{
    private ClaimPathComponent(string? name, int index)
    {
        Name = name;
        Index = index;
    }

    /// <summary>The member name; <c>null</c> when this component is an array index.</summary>
    public string? Name { get; }

    /// <summary>The zero-based array index; <c>-1</c> when this component is a member name.</summary>
    public int Index { get; }

    public static ClaimPathComponent Member(string name) => new(name, -1);

    public static ClaimPathComponent Element(int index) => new(null, index);
}
