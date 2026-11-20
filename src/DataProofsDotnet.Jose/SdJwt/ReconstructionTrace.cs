using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// Where each part of a reconstructed SD-JWT payload came from, recorded by <see cref="SdJwtReconstructor"/> as it
/// resolves the issuer-signed payload against the presented Disclosures (RFC 9901 §7.1). It is the signed-versus-processed
/// comparison at every depth: for each object of the processed payload, which members a Disclosure supplied and how many
/// of its <c>_sd</c> digests stayed unresolved (withheld or decoys); for each array, the elements as issued, in order,
/// each clear, disclosed or undisclosed. SD-JWT VC claim metadata needs exactly this (draft-ietf-oauth-sd-jwt-vc-27
/// §5.6: a claim is selectively disclosable when "directly represented as a Disclosure", and integer and null path
/// components "are evaluated against the array as issued, counting array elements that are not disclosed").
/// Keys are the processed payload's own container nodes, by reference, so the trace is only meaningful for the payload
/// object the same reconstruction returned.
/// </summary>
internal sealed class ReconstructionTrace
{
    /// <summary>How an element of the processed payload got there.</summary>
    public enum Origin
    {
        /// <summary>Signed in the clear, in the issuer-signed payload or inside a Disclosure's value.</summary>
        Clear,

        /// <summary>Supplied directly by a presented Disclosure.</summary>
        Disclosed,

        /// <summary>An array element placeholder no presented Disclosure resolved; absent from the processed array.</summary>
        Undisclosed,
    }

    private readonly Dictionary<JsonObject, ObjectRecord> _objects = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<JsonArray, List<Origin>> _arrays = new(ReferenceEqualityComparer.Instance);

    internal void AddObject(JsonObject output) => _objects[output] = new ObjectRecord();

    internal void AddDisclosedMember(JsonObject output, string name) => _objects[output].Disclosed.Add(name);

    internal void AddUnresolvedDigest(JsonObject output) => _objects[output].UnresolvedDigests++;

    internal void AddArray(JsonArray output) => _arrays[output] = [];

    internal void AddElement(JsonArray output, Origin origin) => _arrays[output].Add(origin);

    /// <summary>Whether a presented Disclosure supplied member <paramref name="name"/> of <paramref name="obj"/>.</summary>
    public bool IsDisclosedMember(JsonObject obj, string name)
        => _objects.TryGetValue(obj, out var record) && record.Disclosed.Contains(name);

    /// <summary>The number of <c>_sd</c> digests of <paramref name="obj"/> that no presented Disclosure resolved.</summary>
    public int UnresolvedDigests(JsonObject obj) => _objects.TryGetValue(obj, out var record) ? record.UnresolvedDigests : 0;

    /// <summary>
    /// The elements of <paramref name="array"/> as issued, in order: undisclosed placeholders included, each with the
    /// index of its value in the processed array (<c>-1</c> for an undisclosed one).
    /// </summary>
    public IReadOnlyList<(Origin Origin, int ProcessedIndex)> AsIssued(JsonArray array)
    {
        if (!_arrays.TryGetValue(array, out var origins))
            return [.. array.Select((_, i) => (Origin.Clear, i))];

        var result = new List<(Origin, int)>(origins.Count);
        var processed = 0;
        foreach (var origin in origins)
            result.Add(origin == Origin.Undisclosed ? (origin, -1) : (origin, processed++));
        return result;
    }

    private sealed class ObjectRecord
    {
        public HashSet<string> Disclosed { get; } = new(StringComparer.Ordinal);

        public int UnresolvedDigests { get; set; }
    }
}
