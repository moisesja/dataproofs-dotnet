using System.Collections;
using System.Text.Json.Serialization;

namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// The value of a proof's <c>previousProof</c> member (FR-1/FR-6): either a single proof
/// id (wire form: bare string) or a set of proof ids (wire form: array of strings).
/// The original wire shape is preserved on round-trip. Immutable: proofs and their options share
/// a reference, so a change to one would change them all (issue #61). No code of the caller's ever holds
/// the ids array, neither through <see cref="Values"/> nor while <see cref="FromValues"/> copies them.
/// </summary>
[JsonConverter(typeof(PreviousProofReferenceJsonConverter))]
public sealed class PreviousProofReference : IEquatable<PreviousProofReference>
{
    private readonly string[] _values;
    private readonly ReadOnlyIds _readOnlyValues;

    private PreviousProofReference(string[] values, bool isArrayForm)
    {
        _values = values;
        _readOnlyValues = new ReadOnlyIds(values);
        IsArrayForm = isArrayForm;
    }

    /// <summary>
    /// The referenced proof ids, in wire order. The list implements <see cref="IReadOnlyList{T}"/> and
    /// nothing else, so no public interface reaches the ids it holds: casting it to an array or to a
    /// writable or non-generic collection interface throws <see cref="InvalidCastException"/> (issue #61).
    /// </summary>
    public IReadOnlyList<string> Values => _readOnlyValues;

    /// <summary><c>true</c> when the wire form is an array; <c>false</c> for a bare string.</summary>
    public bool IsArrayForm { get; }

    /// <summary>Creates a single-id reference that serializes as a bare string.</summary>
    public static PreviousProofReference FromSingle(string proofId)
    {
        ArgumentException.ThrowIfNullOrEmpty(proofId);
        return new PreviousProofReference([proofId], isArrayForm: false);
    }

    /// <summary>
    /// Creates a set reference that serializes as an array of strings. The reference keeps its own copy of the ids,
    /// one no code of the caller's was handed, so changing <paramref name="proofIds"/> afterwards changes nothing.
    /// </summary>
    /// <exception cref="ArgumentException">The set is empty or contains a null/empty id.</exception>
    public static PreviousProofReference FromValues(IEnumerable<string> proofIds)
    {
        ArgumentNullException.ThrowIfNull(proofIds);

        // ToArray passes the array it returns to the CopyTo of a source that implements ICollection<T>, and a
        // collection of the caller's can keep it. The clone is the array this reference keeps and checks below.
        var values = (string[])proofIds.ToArray().Clone();
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

    // Only the read-only interface. The array itself would let a caller rewrite every proof that shares this
    // reference, and so would a writable interface. ReadOnlyCollection<T> is not enough either: its
    // ICollection.SyncRoot returns the array it wraps (PR #62 review).
    private sealed class ReadOnlyIds(string[] ids) : IReadOnlyList<string>
    {
        public int Count => ids.Length;

        public string this[int index] => ids[index];

        public IEnumerator<string> GetEnumerator()
        {
            foreach (var id in ids)
            {
                yield return id;
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
