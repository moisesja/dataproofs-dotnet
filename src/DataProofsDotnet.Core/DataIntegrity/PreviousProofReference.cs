using System.Text.Json.Serialization;

namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// The value of a proof's <c>previousProof</c> member (FR-1/FR-6): either a single proof
/// id (wire form: bare string) or a set of proof ids (wire form: array of strings).
/// The original wire shape is preserved on round-trip.
/// </summary>
[JsonConverter(typeof(PreviousProofReferenceJsonConverter))]
public sealed class PreviousProofReference : IEquatable<PreviousProofReference>
{
    private readonly string[] _values;

    private PreviousProofReference(string[] values, bool isArrayForm)
    {
        _values = values;
        IsArrayForm = isArrayForm;
    }

    /// <summary>The referenced proof ids, in wire order.</summary>
    public IReadOnlyList<string> Values => _values;

    /// <summary><c>true</c> when the wire form is an array; <c>false</c> for a bare string.</summary>
    public bool IsArrayForm { get; }

    /// <summary>Creates a single-id reference that serializes as a bare string.</summary>
    public static PreviousProofReference FromSingle(string proofId)
    {
        ArgumentException.ThrowIfNullOrEmpty(proofId);
        return new PreviousProofReference([proofId], isArrayForm: false);
    }

    /// <summary>Creates a set reference that serializes as an array of strings.</summary>
    /// <exception cref="ArgumentException">The set is empty or contains a null/empty id.</exception>
    public static PreviousProofReference FromValues(IEnumerable<string> proofIds)
    {
        ArgumentNullException.ThrowIfNull(proofIds);
        var values = proofIds.ToArray();
        if (values.Length == 0)
        {
            throw new ArgumentException("previousProof must reference at least one proof.", nameof(proofIds));
        }

        if (values.Any(string.IsNullOrEmpty))
        {
            throw new ArgumentException("previousProof ids must be non-empty strings.", nameof(proofIds));
        }

        return new PreviousProofReference(values, isArrayForm: true);
    }

    /// <summary>Converts a proof id to a single (bare string) reference.</summary>
    public static implicit operator PreviousProofReference(string proofId) => FromSingle(proofId);

    /// <inheritdoc />
    public bool Equals(PreviousProofReference? other)
        => other is not null
            && IsArrayForm == other.IsArrayForm
            && _values.AsSpan().SequenceEqual(other._values);

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as PreviousProofReference);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(IsArrayForm);
        foreach (var value in _values)
        {
            hash.Add(value, StringComparer.Ordinal);
        }

        return hash.ToHashCode();
    }
}
