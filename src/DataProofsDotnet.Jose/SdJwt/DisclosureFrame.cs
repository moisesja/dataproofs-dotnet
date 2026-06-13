namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// A declarative specification of which claims in an Issuer's input claims set are made
/// selectively disclosable, mirroring the claims object's shape (RFC 9901 §5 / §6). Supports the
/// three SD-JWT structuring styles end to end:
/// <list type="bullet">
/// <item>flat — the whole value of a claim becomes one Disclosure (<see cref="Disclose"/>);</item>
/// <item>structured — sub-claims of an object are individually disclosable (<see cref="DiscloseObjectProperties"/>);</item>
/// <item>recursive — a disclosable object whose own sub-claims are also disclosable (<see cref="DiscloseRecursively"/>);</item>
/// <item>array elements — selected elements of an array are individually disclosable (<see cref="DiscloseArrayElements"/>).</item>
/// </list>
/// Build a frame, then pass it to <see cref="SdJwtIssuer"/>. Mutable during construction;
/// the Issuer reads it without retaining a reference.
/// </summary>
public sealed class DisclosureFrame
{
    private readonly Dictionary<string, FrameEntry> _entries = new(StringComparer.Ordinal);

    /// <summary>Mark an object property's entire value as a single selectively disclosable claim (flat / §6.1).</summary>
    /// <param name="claimName">The top-level (or, within a nested frame, sub-) claim name.</param>
    public DisclosureFrame Disclose(string claimName)
    {
        ArgumentException.ThrowIfNullOrEmpty(claimName);
        _entries[claimName] = FrameEntry.Whole();
        return this;
    }

    /// <summary>
    /// Mark an object claim as structured: the named sub-claims inside it become individually
    /// disclosable while the object itself stays in the clear (§6.2).
    /// </summary>
    /// <param name="claimName">The object claim name.</param>
    /// <param name="discloseSubClaims">The sub-claims of that object to make disclosable.</param>
    public DisclosureFrame DiscloseObjectProperties(string claimName, params string[] discloseSubClaims)
    {
        ArgumentException.ThrowIfNullOrEmpty(claimName);
        ArgumentNullException.ThrowIfNull(discloseSubClaims);
        var nested = new DisclosureFrame();
        foreach (var sub in discloseSubClaims)
            nested.Disclose(sub);
        _entries[claimName] = FrameEntry.ForNested(nested, recursive: false);
        return this;
    }

    /// <summary>
    /// Mark an object claim as structured via a fully specified nested frame (lets sub-claims be
    /// themselves structured/recursive).
    /// </summary>
    /// <param name="claimName">The object claim name (stays in the clear).</param>
    /// <param name="nested">The nested frame describing its sub-claims' disclosability.</param>
    public DisclosureFrame DiscloseObject(string claimName, DisclosureFrame nested)
    {
        ArgumentException.ThrowIfNullOrEmpty(claimName);
        ArgumentNullException.ThrowIfNull(nested);
        _entries[claimName] = FrameEntry.ForNested(nested, recursive: false);
        return this;
    }

    /// <summary>
    /// Mark an object claim as recursive: the named sub-claims are individually disclosable AND
    /// the object itself is wrapped in a single parent Disclosure whose value carries their
    /// digests (§6.3).
    /// </summary>
    /// <param name="claimName">The object claim name (itself becomes a Disclosure).</param>
    /// <param name="discloseSubClaims">The sub-claims to make disclosable inside the recursive Disclosure.</param>
    public DisclosureFrame DiscloseRecursively(string claimName, params string[] discloseSubClaims)
    {
        ArgumentException.ThrowIfNullOrEmpty(claimName);
        ArgumentNullException.ThrowIfNull(discloseSubClaims);
        var nested = new DisclosureFrame();
        foreach (var sub in discloseSubClaims)
            nested.Disclose(sub);
        _entries[claimName] = FrameEntry.ForNested(nested, recursive: true);
        return this;
    }

    /// <summary>
    /// Mark a recursive object claim via a fully specified nested frame.
    /// </summary>
    /// <param name="claimName">The object claim name (itself becomes a Disclosure).</param>
    /// <param name="nested">The nested frame for its sub-claims.</param>
    public DisclosureFrame DiscloseRecursiveObject(string claimName, DisclosureFrame nested)
    {
        ArgumentException.ThrowIfNullOrEmpty(claimName);
        ArgumentNullException.ThrowIfNull(nested);
        _entries[claimName] = FrameEntry.ForNested(nested, recursive: true);
        return this;
    }

    /// <summary>
    /// Mark selected elements of an array claim as individually disclosable (RFC 9901 §4.2.4.2):
    /// each chosen index is replaced in the array by an <c>{"...": digest}</c> placeholder.
    /// </summary>
    /// <param name="claimName">The array claim name (stays in the clear).</param>
    /// <param name="indices">The zero-based element indices to make disclosable.</param>
    public DisclosureFrame DiscloseArrayElements(string claimName, params int[] indices)
    {
        ArgumentException.ThrowIfNullOrEmpty(claimName);
        ArgumentNullException.ThrowIfNull(indices);
        foreach (var i in indices)
            if (i < 0)
                throw new ArgumentOutOfRangeException(nameof(indices), "Array element indices must be non-negative.");
        _entries[claimName] = FrameEntry.ForArray(new HashSet<int>(indices));
        return this;
    }

    internal IReadOnlyDictionary<string, FrameEntry> Entries => _entries;

    internal sealed class FrameEntry
    {
        private FrameEntry(FrameKind kind, DisclosureFrame? nested, bool recursive, IReadOnlySet<int>? arrayIndices)
        {
            Kind = kind;
            Nested = nested;
            Recursive = recursive;
            ArrayIndices = arrayIndices;
        }

        public FrameKind Kind { get; }
        public DisclosureFrame? Nested { get; }
        public bool Recursive { get; }
        public IReadOnlySet<int>? ArrayIndices { get; }

        public static FrameEntry Whole() => new(FrameKind.WholeValue, null, false, null);
        public static FrameEntry ForNested(DisclosureFrame nested, bool recursive) => new(FrameKind.NestedObject, nested, recursive, null);
        public static FrameEntry ForArray(IReadOnlySet<int> indices) => new(FrameKind.ArrayElements, null, false, indices);
    }

    internal enum FrameKind
    {
        WholeValue,
        NestedObject,
        ArrayElements,
    }
}
